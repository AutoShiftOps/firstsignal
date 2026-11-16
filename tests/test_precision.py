"""Negative and boundary cases: lines that must not produce a misleading finding (#61)."""

import pytest

from firstsignal.analyzer import analyze
from firstsignal.patterns import PACKS, resolve_packs

ALL = resolve_packs(["all"])


def keys(line: str) -> set[str]:
    return set(analyze(line, ALL).findings)


# ---- PostgreSQL: a rejected session is not a crash -------------------------------------------

@pytest.mark.parametrize("line", [
    '2026-11-14 09:41:02.118 UTC [3141] FATAL:  password authentication failed for user "app"',
    '2026-11-14 09:41:02 UTC [3141] FATAL:  no pg_hba.conf entry for host "10.0.0.5", user "app"',
    '2026-11-14 09:41:02 UTC [3141] FATAL:  database "orders" does not exist',
    '2026-11-14 09:41:02 UTC [3141] FATAL:  role "reporting" does not exist',
])
def test_postgres_rejected_session_is_not_a_crash(line):
    found = keys(line)
    assert "pg_connection_rejected" in found
    assert "panic_fatal" not in found


def test_postgres_panic_is_still_a_crash():
    assert "panic_fatal" in keys("2026-11-14 09:41:05 UTC [3150] PANIC:  could not write to file")


@pytest.mark.parametrize("line", [
    "2026-11-14T09:42:05Z FATAL [api] crashed",
    "FATAL ERROR: Reached heap limit Allocation failed",
    "fatal error: all goroutines are asleep - deadlock!",
])
def test_application_fatal_is_still_a_crash(line):
    assert "panic_fatal" in keys(line)


def test_non_fatal_is_not_a_crash():
    assert "panic_fatal" not in keys("WARN retry was non-fatal, continuing")


# ---- Kubernetes eviction needs Kubernetes phrasing ---------------------------------------------

@pytest.mark.parametrize("line", [
    "INFO cache: evicted 1200 keys from LRU",
    "DEBUG session 81f2 evicted after idle timeout",
    "redis: evicted_keys:4210",
])
def test_cache_eviction_is_not_a_pod_eviction(line):
    assert "k8s_evicted" not in keys(line)


@pytest.mark.parametrize("line", [
    "Warning  Evicted   pod/api-7d9f   The node was low on resource: memory.",
    "kubelet: eviction manager: pods api_prod evicted successfully",
    "Pod api-7d9f was evicted",
    'status: {"phase": "Failed", "reason": "Evicted"}',
])
def test_pod_eviction_is_found(line):
    assert "k8s_evicted" in keys(line)


# ---- Slowness is a report, not a measurement ---------------------------------------------------

def test_slow_log_settings_are_not_slowness():
    assert "slow" not in keys("INFO slow query log enabled, threshold 2000ms")


def test_slow_report_is_titled_as_a_report():
    a = analyze("WARN slow query: 4210 ms SELECT * FROM orders", ALL)
    f = a.findings["slow"]
    assert f.title == "Slowness reported"
    assert "not a latency measurement" in f.advice


# ---- Access denied says what the line shows ---------------------------------------------------

def test_access_denied_title_does_not_assume_files():
    f = analyze("ERROR access denied for user app", ALL).findings["permission"]
    assert f.title == "Access denied" and "HTTP 403" in f.advice


# ---- Packs ---------------------------------------------------------------------------------------

def test_repeated_packs_are_not_duplicated():
    assert len(resolve_packs(["nginx", "nginx"])) == len(PACKS["nginx"])
    assert len(resolve_packs(["all", "core"])) == len(resolve_packs(["all"]))
    found = analyze("upstream timed out", resolve_packs(["nginx", "nginx"])).findings
    assert found["nginx_upstream_timeout"].count == 1


def test_pattern_keys_are_unique():
    all_keys = [p.key for pack in PACKS.values() for p in pack]
    assert len(all_keys) == len(set(all_keys))


# ---- Wording: no causal claims outside the AI hypothesis ---------------------------------------

def test_report_does_not_claim_cause(example_log, tmp_path, monkeypatch, capsys):
    from firstsignal import cli

    monkeypatch.chdir(tmp_path)
    cli.run(["file", "--path", str(example_log), "--no-history"])
    console = capsys.readouterr().out.lower()
    report = (tmp_path / "out" / "report.md").read_text().lower()
    for text in (console, report):
        assert "root cause" not in text
        assert "more likely cause" not in text
    assert "earliest observed matching signature" in console
    assert "not proof of cause" in report
