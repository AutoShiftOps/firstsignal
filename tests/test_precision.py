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
    report = (tmp_path / "out" / "report.md").read_text(encoding="utf-8").lower()
    for text in (console, report):
        assert "root cause" not in text
        assert "more likely cause" not in text
    assert "earliest observed matching signature" in console
    assert "not proof of cause" in report


# ---- #73: phrasings the corpus found, and their near misses ------------------------------------

@pytest.mark.parametrize("line,key", [
    ("HikariPool-1 - Connection is not available, request timed out after 30000ms.", "conn_limit"),
    ("Cannot get a connection, pool error Timeout waiting for idle object", "conn_limit"),
    ("Scheduled restart job, restart counter is at 3.", "restart_loop"),
    ("consumer poll timeout has expired", "timeout"),
    ("lock timeout has been exceeded", "timeout"),
    ('{"level":40,"msg":"request slow","responseTime":4210}', "slow"),
    ("upstream call was slow (2.3s)", "slow"),
    ("LOG:  database system is shut down", "pg_unavailable"),
])
def test_new_phrasings_are_found(line, key):
    assert key in keys(line)


@pytest.mark.parametrize("line,key", [
    ("Scheduled restart job, restart counter is at 1.", "restart_loop"),   # one restart is not a loop
    ("LOG:  database system is ready to accept connections", "pg_unavailable"),
    ("timeout settings: connect=2s read=10s", "timeout"),
    ("the network is slow to start on boot", "slow"),
    ("connection pool stats: active=3 idle=7", "conn_limit"),
])
def test_new_phrasings_do_not_overreach(line, key):
    assert key not in keys(line)


def test_client_facing_results_follow_their_cause_at_the_same_second():
    from firstsignal.analyzer import time_order

    text = ('=== SOURCE: access.log ===\n10.0.0.1 - - [05/Oct/2026:03:14:02 +0000] "GET / HTTP/1.1" 504 0\n\n'
            "=== SOURCE: error.log ===\n2026/10/05 03:14:02 [error] 31#31: *1 upstream timed out\n")
    order, _ = time_order(analyze(text, ALL))
    assert order.index("timeout") < order.index("http_5xx")
