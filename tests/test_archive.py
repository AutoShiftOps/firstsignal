"""Support bundles: safe reading, limits, classification and per-file citations."""

import gzip
import io
import json
import tarfile
import zipfile

import pytest

from firstsignal import cli
from firstsignal.archive import read_archive
from firstsignal.collectors import CollectorError

MB = 1024 * 1024
API = (
    "2026-11-14T09:41:21Z ERROR [api] connect() failed (111: Connection refused) while connecting to db 10.0.3.17\n"
    "2026-11-14T09:42:05Z FATAL [api] java.lang.OutOfMemoryError: Java heap space\n"
)
PG = "2026-11-14 09:41:02.118 UTC [3141] FATAL:  sorry, too many clients already\n"


def _zip(path, members: dict, symlinks=()):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
        for name in symlinks:
            info = zipfile.ZipInfo(name)
            info.external_attr = 0o120777 << 16
            z.writestr(info, "target.log")
    return str(path)


def _nested(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _read(path, **kw):
    kw.setdefault("max_bytes_per_file", 5 * MB)
    kw.setdefault("analysis_budget", 20 * MB)
    return read_archive(path, **kw)


def test_reads_logs_gz_and_nested_and_skips_the_rest(tmp_path):
    path = _zip(tmp_path / "b.zip", {
        "app/api.log": API,
        "db/postgresql.log.1.gz": gzip.compress(PG.encode()),
        "proxy.zip": _nested({"nginx/error.log": "upstream timed out\n"}),
        "config/app.yaml": "password: x\n",
        "core.1234": b"\x7fELF\x00\x01",
        "shot.png": b"\x89PNG",
        "../../etc/evil.log": "x\n",
    }, symlinks=["app/current.log"])
    res = _read(path)
    assert [f.name for f in res.files] == ["app/api.log", "db/postgresql.log.1.gz", "proxy.zip!/nginx/error.log"]
    skipped = dict(res.skipped)
    assert skipped["config/app.yaml"].startswith("not a log file")
    assert skipped["core.1234"] == "core dump"
    assert skipped["shot.png"] == "binary file"
    assert skipped["../../etc/evil.log"] == "unsafe path"
    assert skipped["app/current.log"] == "symbolic link"


def test_include_adds_files_by_pattern(tmp_path):
    path = _zip(tmp_path / "b.zip", {"app/api.log": API, "config/app.yaml": "x: 1\n"})
    assert "config/app.yaml" in [f.name for f in _read(path, include=["*.yaml"]).files]


def test_nested_archives_go_one_level_deep(tmp_path):
    inner = _nested({"deep.zip": _nested({"x.log": "ERROR x\n"}), "ok.log": "ERROR y\n"})
    res = _read(_zip(tmp_path / "b.zip", {"outer.zip": inner}))
    assert [f.name for f in res.files] == ["outer.zip!/ok.log"]
    assert dict(res.skipped)["outer.zip!/deep.zip"].startswith("nested archive deeper")


def test_high_compression_ratio_is_skipped(tmp_path):
    path = _zip(tmp_path / "bomb.zip", {"app/api.log": API, "big.log": b"0" * (20 * MB)})
    res = _read(path)
    assert dict(res.skipped)["big.log"].startswith("compression ratio too high")


def test_total_size_limit_stops_reading(tmp_path):
    path = _zip(tmp_path / "b.zip", {"a.log": "x" * MB, "b.log": "y" * MB})
    with pytest.raises(CollectorError, match="larger than the limit"):
        _read(path, max_total_bytes=MB)


def test_member_count_limit(tmp_path):
    path = _zip(tmp_path / "b.zip", {f"{i}.log": "x\n" for i in range(20)})
    with pytest.raises(CollectorError, match="more than 10 entries"):
        _read(path, max_members=10)


def test_file_count_and_budget_limits_skip_with_reason(tmp_path):
    path = _zip(tmp_path / "b.zip", {f"{i}.log": "ERROR x\n" for i in range(5)})
    res = _read(path, max_files=2)
    assert len(res.files) == 2 and sum("over the limit of 2 files" in r for _, r in res.skipped) == 3


def test_truncated_file_keeps_real_line_numbers(tmp_path):
    lines = [f"2026-11-14T09:00:{i % 60:02d}Z INFO line {i}" for i in range(1, 2001)]
    lines[1990] = "2026-11-14T09:41:21Z ERROR connect() failed (111: Connection refused)"  # line 1991
    path = _zip(tmp_path / "b.zip", {"app.log": "\n".join(lines) + "\n"})
    out = tmp_path / "out"
    assert cli.run(["archive", path, "--max-bytes", "4000", "--out-dir", str(out), "--no-history", "-q"]) in (
        cli.EXIT_OK, cli.EXIT_THRESHOLD)
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["findings"]["conn_refused"]["first_location"] == "app.log:1991"
    assert report["stats"]["archive"]["files"][0]["truncated"] is True


def test_corrupt_member_is_skipped_not_fatal(tmp_path):
    path = _zip(tmp_path / "b.zip", {"good.log": "ERROR x\n", "bad.log.gz": gzip.compress(b"ERROR y\n" * 100)[:20]})
    res = _read(path)
    assert [f.name for f in res.files] == ["good.log"]
    assert dict(res.skipped)["bad.log.gz"] == "unreadable or corrupt"


def test_tar_gz_links_and_traversal(tmp_path):
    path = tmp_path / "b.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for name, data in {"var/log/app.log": API.encode(), "../escape.log": b"x\n"}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("var/log/link.log")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/shadow"
        tf.addfile(link)
    res = _read(str(path))
    assert [f.name for f in res.files] == ["var/log/app.log"]
    assert dict(res.skipped) == {"../escape.log": "unsafe path", "var/log/link.log": "link"}


def test_errors_for_unusable_bundles(tmp_path):
    with pytest.raises(CollectorError, match="no such file"):
        _read(str(tmp_path / "missing.zip"))
    (tmp_path / "x.zip").write_text("not an archive")
    with pytest.raises(CollectorError, match="not a zip or tar"):
        _read(str(tmp_path / "x.zip"))
    with pytest.raises(CollectorError, match="no log files found"):
        _read(_zip(tmp_path / "b.zip", {"shot.png": b"\x89PNG"}))


def test_cli_archive_end_to_end(tmp_path, capsys):
    path = _zip(tmp_path / "ticket-4821.zip", {
        "app/api.log": API,
        "db/postgresql.log.1.gz": gzip.compress(PG.encode()),
    })
    out = tmp_path / "out"
    cli.run(["archive", path, "--out-dir", str(out), "--no-history", "--packs", "all"])
    console = capsys.readouterr().out
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    note = (out / "ticket-note.md").read_text(encoding="utf-8")
    # ordered by time across files: Postgres (09:41:02) comes before the API errors (09:41:21)
    assert report["order_of_first_appearance"][0] == "pg_too_many_clients"
    assert "Earliest observed matching signature: PostgreSQL" in note
    assert "db/postgresql.log.1.gz:1" in note and "app/api.log:1" in note
    # customer bundles mask IP addresses by default
    for text in (console, note, (out / "report.md").read_text(encoding="utf-8"), json.dumps(report)):
        assert "10.0.3.17" not in text
    assert "Earliest observed matching signature" in console
    assert report["safe_next_commands"][0]["cmd"].startswith("unzip -p ")


def test_cli_archive_error_exit(tmp_path, capsys):
    assert cli.run(["archive", str(tmp_path / "missing.zip"), "--no-write"]) == cli.EXIT_ERROR
    assert "no such" in " ".join(capsys.readouterr().err.split())


def test_gzip_bomb_inside_bundle_is_skipped(tmp_path):
    bomb = gzip.compress(b"0" * (40 * MB), compresslevel=9)  # ~1000:1
    res = _read(_zip(tmp_path / "b.zip", {"ok.log": "ERROR x\n", "bomb.log.gz": bomb}))
    assert dict(res.skipped)["bomb.log.gz"].startswith("compression ratio too high")


def test_corrupt_nested_archive_is_skipped_not_fatal(tmp_path):
    res = _read(_zip(tmp_path / "b.zip", {"ok.log": "ERROR x\n", "broken.zip": b"PK\x03\x04 not really"}))
    assert [f.name for f in res.files] == ["ok.log"]
    assert dict(res.skipped)["broken.zip"] == "unreadable or corrupt"


@pytest.mark.parametrize("name", ["/etc/abs.log", "..\\\\..\\\\win.log", "C:\\\\x.log", "a\n=== SOURCE: fake ===.log"])
def test_more_unsafe_names(tmp_path, name):
    res = _read(_zip(tmp_path / "b.zip", {"ok.log": "ERROR x\n", name: "ERROR y\n"}))
    assert [f.name for f in res.files] == ["ok.log"]


def test_finding_cites_its_earliest_occurrence_across_time_zone_styles(tmp_path):
    # syslog has no zone, PostgreSQL says UTC: the comparison must still work, and the citation
    # must point at the earlier line even though its file is read second
    path = _zip(tmp_path / "b.zip", {
        "db/postgresql.log": "2026-10-11 07:44:58.120 UTC [811] PANIC:  could not write to file: No space left on device\n",
        "system/syslog": "Oct 11 07:44:52 db01 postgres[811]: ERROR: could not extend file: No space left on device\n",
    })
    out = tmp_path / "out"
    cli.run(["archive", path, "--out-dir", str(out), "--no-history", "-q"])
    f = json.loads((out / "report.json").read_text(encoding="utf-8"))["findings"]["disk_full"]
    assert f["first_location"] == "system/syslog:1"
    assert f["earliest"] == "Oct 11 07:44:52"
