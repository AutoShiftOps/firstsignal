"""Incident history correctness (#62): identity, growth, clock skew, bad records, concurrent writes."""

import json
import threading
from datetime import datetime, timedelta, timezone

from firstsignal import cli, memory
from firstsignal.analyzer import analyze
from firstsignal.redact import Redactor
from firstsignal.watch import Watcher

T0 = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)
POOL = "ERROR connection pool exhausted\n"
TIMEOUT = "ERROR upstream timed out\n"
OOM = "ERROR Out of memory: Killed process 42\n"
DISK = "ERROR No space left on device\n"


def run(core, path, text, minutes=0, target="api"):
    inc = memory.from_analysis(analyze(text, core), target, "file", T0 + timedelta(minutes=minutes))
    return memory.remember(path, inc)


# ---- identity --------------------------------------------------------------------------------

def test_growing_incident_stays_one_record(core, tmp_path):
    path = tmp_path / "h.jsonl"
    first, _ = run(core, path, POOL)
    second, matches = run(core, path, POOL * 3 + TIMEOUT + OOM, minutes=5)
    rows = memory.load(path)
    assert len(rows) == 1 and second.id == first.id and matches == []
    assert rows[0].keys == ["conn_limit", "oom_kill", "timeout"]
    assert rows[0].first == "conn_limit"                 # what came first stays first
    assert rows[0].counts["conn_limit"] == 3 and rows[0].severity == "critical"
    assert rows[0].runs == 2


def test_shrinking_rerun_keeps_what_was_seen(core, tmp_path):
    path = tmp_path / "h.jsonl"
    run(core, path, POOL + OOM)
    run(core, path, POOL, minutes=5)
    (row,) = memory.load(path)
    assert row.keys == ["conn_limit", "oom_kill"] and row.severity == "critical"
    assert row.counts == {"conn_limit": 1, "oom_kill": 1}


def test_unrelated_findings_on_same_target_are_a_new_incident(core, tmp_path):
    path = tmp_path / "h.jsonl"
    run(core, path, POOL)
    run(core, path, DISK, minutes=5)
    assert len(memory.load(path)) == 2


def test_gap_longer_than_the_window_is_a_new_incident(core, tmp_path):
    path = tmp_path / "h.jsonl"
    run(core, path, POOL)
    run(core, path, POOL, minutes=90)
    assert len(memory.load(path)) == 2


# ---- clock skew ------------------------------------------------------------------------------

def test_record_far_in_the_future_does_not_absorb_new_runs(core, tmp_path):
    path = tmp_path / "h.jsonl"
    run(core, path, POOL, minutes=180)     # written by a machine with its clock 3 hours ahead
    run(core, path, POOL)
    run(core, path, POOL, minutes=10)
    assert len(memory.load(path)) == 2


def test_small_clock_skew_is_tolerated(core, tmp_path):
    path = tmp_path / "h.jsonl"
    run(core, path, POOL, minutes=2)
    run(core, path, POOL)                  # looks 2 minutes earlier
    (row,) = memory.load(path)
    assert row.runs == 2
    assert row.last_seen_at == (T0 + timedelta(minutes=2)).isoformat(timespec="seconds")  # never moves back


# ---- bad records -----------------------------------------------------------------------------

def _write(path, rows):
    path.write_text("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows))


def _record(id_, recorded, last):
    return {"id": id_, "recorded_at": recorded, "last_seen_at": last, "target": "api", "source": "file",
            "severity": "high", "keys": ["conn_limit"], "first": "conn_limit", "counts": {"conn_limit": 1}}


def test_naive_timestamps_are_read_as_utc_and_bad_ones_are_kept_aside(core, tmp_path):
    path = tmp_path / "h.jsonl"
    _write(path, [
        _record("naive001", "2026-02-01T09:00:00", "2026-02-01T09:05:00"),
        _record("badtime1", "yesterday", "soon"),
        "{not json",
    ])
    stored = memory.read(path)
    assert [i.id for i in stored.incidents] == ["naive001"]
    assert stored.incidents[0].last_seen_at == "2026-02-01T09:05:00+00:00"
    assert len(stored.unreadable) == 2
    # a new run compares against the naive record without crashing, and keeps the bad lines
    _, matches = run(core, path, POOL)
    assert [m.incident.id for m in matches] == ["naive001"] and matches[0].days_ago == 27
    text = path.read_text(encoding="utf-8")
    assert '"yesterday"' in text and "{not json" in text


def test_history_list_warns_about_unreadable_lines(tmp_path, capsys):
    path = tmp_path / "h.jsonl"
    _write(path, [_record("good0001", "2026-02-01T09:00:00Z", "2026-02-01T09:05:00Z"), "{not json"])
    assert cli.run(["history", "--history", str(path), "list"]) == cli.EXIT_OK
    out = capsys.readouterr()
    assert "good0001" in out.out and "1 line(s)" in " ".join(out.err.split())


def test_note_and_forget_keep_unreadable_lines(core, tmp_path):
    path = tmp_path / "h.jsonl"
    rec, _ = run(core, path, POOL)
    with open(path, "a") as fh:
        fh.write("{not json\n")
    memory.set_note(path, rec.id, "raised pool")
    memory.forget(path, "nope")
    assert "{not json" in path.read_text(encoding="utf-8")


# ---- concurrent writes -----------------------------------------------------------------------

def test_concurrent_runs_do_not_lose_records(core, tmp_path):
    path = tmp_path / "h.jsonl"
    errors = []

    def worker(n):
        try:
            for i in range(15):
                run(core, path, POOL, target=f"svc-{n}-{i}")
        except Exception as exc:  # noqa: BLE001 - surface any failure from the thread
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(memory.load(path)) == 60
    assert not list(tmp_path.glob("h.jsonl.*.tmp"))


# ---- watch -----------------------------------------------------------------------------------

def test_watch_saves_growth_that_only_changes_counts(core, tmp_path):
    hist = tmp_path / "h.jsonl"
    t = [T0]
    windows = iter([POOL, POOL * 4, POOL * 9])
    w = Watcher(lambda: next(windows), core, None, Redactor(), "api", "file", hist, now=lambda: t[0])
    for _ in range(3):
        w.tick()
        t[0] += timedelta(seconds=15)
    (row,) = memory.load(hist)
    assert row.counts == {"conn_limit": 9} and row.runs == 3


def test_reports_say_what_counts_cover(example_log, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cli.run(["file", "--path", str(example_log), "--no-history", "--no-write", "--json"])
    assert json.loads(capsys.readouterr().out)["stats"]["counts_scope"] == "the whole input"
    cli.run(["file", "--path", str(example_log), "--no-history", "--max-bytes", "600"])
    assert json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))["stats"]["truncated"] is True
    assert "Counts cover the most recent part" in " ".join(capsys.readouterr().out.split())
    assert "- Counts cover: the most recent part" in (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
