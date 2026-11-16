"""Every output boundary must be free of secrets: console, Markdown, JSON, HTML, AI payload, history."""

import json

import pytest

from firstsignal import ai, cli
from firstsignal.analyzer import analyze
from firstsignal.patterns import resolve_packs
from firstsignal.redact import Redactor
from firstsignal.reporter import build_meta

SECRETS = [
    "MIIEowIBAAKCAQEAu1SU1LfV",          # private-key body
    "VTLw7onLRnrq0",                     # second key line
    "abc123",                            # short bearer token
    "9f8a7c6b5d4e3f2a1b0c9d8e7f6a5b4c",  # unlabeled hex secret
    "Zk82hQ0pLx7Vb3nRt9WqY4mK",          # unlabeled random token
    "hunter2pass",                       # password in a URL
]

LOG = """2026-03-01T09:41:00Z INFO  [api] starting
2026-03-01T09:41:01Z ERROR [api] tls setup failed, key was:
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun
VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK
-----END RSA PRIVATE KEY-----
2026-03-01T09:41:02Z ERROR [api] upstream 503 Service Unavailable, Authorization: Bearer abc123
2026-03-01T09:41:03Z ERROR [api] connection refused, failed key 9f8a7c6b5d4e3f2a1b0c9d8e7f6a5b4c
2026-03-01T09:41:04Z ERROR [api] timeout calling payments session Zk82hQ0pLx7Vb3nRt9WqY4mK
2026-03-01T09:41:05Z FATAL [api] out of memory, db postgres://app:hunter2pass@db:5432/x
"""


@pytest.fixture
def secret_log(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "secret.log"
    path.write_text(LOG)
    return path


def _assert_clean(text: str, where: str):
    for s in SECRETS:
        assert s not in text, f"{s!r} leaked into {where}"


def test_reports_console_and_history_are_clean(secret_log, tmp_path, capsys):
    history = tmp_path / "history.jsonl"
    assert cli.run(["file", "--path", str(secret_log), "--html", "--history", str(history)]) in (
        cli.EXIT_OK, cli.EXIT_THRESHOLD)
    captured = capsys.readouterr()
    _assert_clean(captured.out + captured.err, "console")
    for name in ("report.md", "report.json", "report.html"):
        _assert_clean((tmp_path / "out" / name).read_text(encoding="utf-8"), name)
    _assert_clean(history.read_text(encoding="utf-8"), "history")


def test_json_stdout_is_clean(secret_log, capsys):
    cli.run(["file", "--path", str(secret_log), "--json", "--no-write", "--no-history"])
    out = capsys.readouterr().out
    json.loads(out)
    _assert_clean(out, "--json output")


def test_ai_payload_is_clean():
    analysis = analyze(LOG, resolve_packs(["core"]), redactor=Redactor())
    _assert_clean(ai.build_prompt(analysis, build_meta("file", "secret.log", "n/a")), "AI payload")


def test_no_redact_still_shows_raw_text(secret_log, capsys):
    cli.run(["file", "--path", str(secret_log), "--json", "--no-write", "--no-history", "--no-redact"])
    assert "hunter2pass" in capsys.readouterr().out
