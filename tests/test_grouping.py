"""Multi-line stack traces are one event (#12)."""

from firstsignal.analyzer import analyze
from firstsignal.grouping import MAX_EVENT_LINES, Grouper
from firstsignal.patterns import resolve_packs

ALL = resolve_packs(["all"])

JAVA = """2026-11-14 09:41:25,118 ERROR [exec-3] c.a.OrderService - Order lookup failed
org.springframework.dao.DataAccessResourceFailureException: Unable to acquire JDBC Connection
\tat com.acme.OrderService.find(OrderService.java:42)
\tat com.acme.Api.handle(Api.java:17)
Caused by: org.hibernate.exception.JDBCConnectionException: Unable to acquire JDBC Connection
\t... 87 common frames omitted
Caused by: java.net.ConnectException: Connection refused
\tat java.base/sun.nio.ch.Net.connect0(Native Method)
\t... 101 more
"""

PYTHON = """2026-11-14 09:41:25,118 ERROR app: request failed
Traceback (most recent call last):
  File "/app/db.py", line 12, in connect
    sock.connect(addr)
ConnectionRefusedError: [Errno 111] Connection refused

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/app/main.py", line 30, in handler
    db.connect()
TimeoutError: timed out waiting for database
"""

GO = """panic: runtime error: index out of range [5] with length 3

goroutine 1 [running]:
main.handler(0xc000010000)
\t/app/main.go:21 +0x1d
net/http.(*conn).serve(0xc0000b4000)
\t/usr/local/go/src/net/http/server.go:2009 +0x5e
exit status 2
"""

NODE = """Error: connect ECONNREFUSED 10.0.0.5:5432
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1555:16)
    at Pool.connect (/app/node_modules/pg-pool/index.js:45:11)
"""

NEXT = "2026-11-14 09:41:30,000 INFO app: next request\n"


def groups(text):
    g, out = Grouper(), []
    for no, raw in enumerate(text.splitlines(), 1):
        out += g.feed(no, raw)
    return out + g.flush()


def test_each_trace_is_one_event():
    for trace in (JAVA, PYTHON, GO, NODE):
        events = groups(trace + NEXT)
        assert len(events) == 2, trace.splitlines()[0]
        assert len(events[0].lines) == len(trace.strip("\n").splitlines())


def test_java_example_is_the_deepest_cause():
    a = analyze(JAVA, ALL, track_locations=True)
    f = a.findings["conn_refused"]
    assert f.count == 1 and f.first_location == "line 7"
    assert f.examples[0].endswith("Caused by: java.net.ConnectException: Connection refused")
    assert f.examples[0].startswith("2026-11-14 09:41:25,118 ERROR")


def test_python_chained_traceback_is_one_crash_with_its_exceptions():
    a = analyze(PYTHON + NEXT, ALL, track_locations=True)
    assert a.stats["events"] == 2 and a.stats["multiline_events"] == 1
    crash = a.findings["panic_fatal"]
    assert crash.count == 1 and crash.examples[0].endswith("TimeoutError: timed out waiting for database")
    assert a.findings["conn_refused"].first_location == "line 5"


def test_go_panic_and_node_error():
    assert analyze(GO, ALL).findings["panic_fatal"].count == 1
    assert analyze(NODE, ALL).findings["conn_refused"].count == 1


def test_repeated_traces_count_once_each():
    a = analyze((JAVA + NEXT) * 3, ALL)
    assert a.findings["conn_refused"].count == 3
    assert a.stats["lines_total"] == 30 and a.stats["events"] == 6


def test_counts_were_inflated_by_frames_before():
    # a trace whose every frame mentions a timeout class used to count once per frame
    trace = "ERROR call failed\n" + "".join(
        f"\tat com.acme.Client.read(Client.java:{i}) read timeout\n" for i in range(20))
    assert analyze(trace, ALL).findings["timeout"].count == 1


def test_docker_and_kubectl_prefixes():
    docker = "".join(f"2026-11-14T09:41:25.{i:03d}Z {line}\n" for i, line in enumerate(JAVA.splitlines()))
    kubectl = "".join(f"[pod/api-7d9f/api] {line}\n" for line in JAVA.splitlines())
    for text in (docker, kubectl):
        assert len(groups(text)) == 1
        assert analyze(text, ALL).findings["conn_refused"].count == 1


def test_json_lines_and_plain_lines_stay_separate():
    text = '{"level":"error","msg":"connection refused"}\n{"level":"error","msg":"connection refused"}\n'
    assert analyze(text, ALL).findings["conn_refused"].count == 2
    plain = "ERROR connection refused\nERROR connection refused\n"
    assert len(groups(plain)) == 2


def test_blank_line_ends_an_ordinary_event():
    assert len(groups("ERROR a\n\n    indented after a blank\n")) == 2


def test_runaway_continuation_is_split():
    text = "ERROR start\n" + "    more\n" * (MAX_EVENT_LINES + 50)
    events = groups(text)
    assert len(events) == 2 and len(events[0].lines) == MAX_EVENT_LINES


def test_trace_in_a_bundle_cites_the_exception_line(tmp_path):
    import json
    import zipfile

    from firstsignal import cli

    path = tmp_path / "b.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("app/server.log", "2026-11-14 09:41:20,000 INFO app: start\n" + JAVA)
    out = tmp_path / "out"
    cli.run(["archive", str(path), "--out-dir", str(out), "--no-history", "--packs", "all", "-q"])
    f = json.loads((out / "report.json").read_text())["findings"]["conn_refused"]
    assert f["first_location"] == "app/server.log:8" and f["count"] == 1
