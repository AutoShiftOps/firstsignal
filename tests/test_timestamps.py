"""Timestamps in the formats real logs use, so findings can be ordered in time across files."""

import gzip
import json
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from firstsignal import cli
from firstsignal.parsing import parse_line, to_datetime

NOW = datetime(2026, 11, 16, 12, 0)
UTC = timezone.utc


@pytest.mark.parametrize("line,expected", [
    # ISO and near-ISO
    ("2026-11-14T09:41:25Z ERROR x", datetime(2026, 11, 14, 9, 41, 25, tzinfo=UTC)),
    ("2026-11-14 09:41:25,118 ERROR [main] x", datetime(2026, 11, 14, 9, 41, 25, 118000)),
    ("2026-11-14 09:41:02.1 UTC [3141] FATAL:  x", datetime(2026, 11, 14, 9, 41, 2, 100000, tzinfo=UTC)),
    ("2026-11-14T09:41:25.123456789+05:30 x",
     datetime(2026, 11, 14, 9, 41, 25, 123456, tzinfo=timezone(timedelta(hours=5, minutes=30)))),
    ("2026-11-14T09:41:25+0100 x", datetime(2026, 11, 14, 9, 41, 25, tzinfo=timezone(timedelta(hours=1)))),
    # nginx error log and Go's log package
    ("2026/11/14 09:41:25 [error] 77#77: *1023 upstream timed out", datetime(2026, 11, 14, 9, 41, 25)),
    # Apache / nginx access log
    ('10.0.0.1 - - [14/Nov/2026:09:41:25 +0000] "GET / HTTP/1.1" 502 157',
     datetime(2026, 11, 14, 9, 41, 25, tzinfo=UTC)),
    # syslog and journalctl's default output: no year
    ("Nov 14 09:41:25 web01 sshd[812]: error: connect failed", datetime(2026, 11, 14, 9, 41, 25)),
    ("Jan  2 03:04:05 host app: ERROR x", datetime(2026, 1, 2, 3, 4, 5)),
    ("<13>Nov 14 09:41:25 host app: ERROR x", datetime(2026, 11, 14, 9, 41, 25)),
    # JSON epoch seconds and milliseconds (pino, bunyan)
    ('{"time": 1731577285123, "level": 50, "msg": "boom"}', datetime(2024, 11, 14, 9, 41, 25, 123000, tzinfo=UTC)),
    ('{"ts": 1731577285, "msg": "x"}', datetime(2024, 11, 14, 9, 41, 25, tzinfo=UTC)),
])
def test_formats(line, expected):
    assert to_datetime(parse_line(line).timestamp, NOW) == expected


@pytest.mark.parametrize("line", [
    "error at line 12/34 nothing here",
    "seen Nov 14 09:41:25 mid-line",          # syslog form only counts at the start of a line
    "order 1731577285 failed",                # bare numbers in plain text are not times
])
def test_not_timestamps(line):
    assert parse_line(line).timestamp is None


def test_syslog_year_rolls_back_over_new_year():
    assert to_datetime("Dec 31 23:00:00", datetime(2027, 1, 1, 5, 0)) == datetime(2026, 12, 31, 23, 0)


def test_unparseable_values_are_none():
    for value in (None, "", "yesterday", "2026-13-40T99:99:99Z", "99/Foo/2026:09:41:25 +0000"):
        assert to_datetime(value, NOW) is None


def test_archive_orders_nginx_and_syslog_by_time(tmp_path):
    # syslog lines carry no year, so the test uses a recent day for all three files
    d = datetime.now() - timedelta(days=2)
    path = tmp_path / "b.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("app/api.log", f"{d:%Y-%m-%d}T09:41:30Z ERROR [api] HTTP 503 Service Unavailable\n")
        z.writestr("nginx/error.log", f"{d:%Y/%m/%d} 09:41:25 [error] 77#77: *1 upstream timed out (110: "
                                      "Connection timed out) while reading response header from upstream\n")
        z.writestr("var/log/syslog.1.gz", gzip.compress(
            f"{d:%b} {d.day:2d} 09:41:20 db01 kernel: Out of memory: Killed process 42\n".encode()))
    out = tmp_path / "out"
    cli.run(["archive", str(path), "--out-dir", str(out), "--no-history", "--packs", "all", "-q"])
    report = json.loads((out / "report.json").read_text())
    order = report["order_of_first_appearance"]
    assert order.index("oom_kill") < order.index("nginx_upstream_timeout") < order.index("http_5xx")
    assert all(report["findings"][k]["earliest"] for k in order)
