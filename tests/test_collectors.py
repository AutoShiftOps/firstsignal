import gzip
import subprocess

import pytest

from firstsignal import collectors
from firstsignal.collectors import CollectorError


class FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


@pytest.fixture
def calls(monkeypatch):
    seen = []

    def fake_run(cmd, **kw):
        seen.append((cmd, kw))
        return FakeProc(stdout="ok\n")

    monkeypatch.setattr(collectors.subprocess, "run", fake_run)
    return seen


def test_journal_command(calls):
    assert collectors.from_journal("nginx", "10 min ago") == "ok\n"
    cmd, kw = calls[0]
    assert cmd == ["journalctl", "-u", "nginx", "--since", "10 min ago", "--no-pager", "-o", "short-iso"]
    assert "shell" not in kw


def test_docker_keeps_stderr(calls):
    collectors.from_docker("api", "1h", engine="docker")
    cmd, kw = calls[0]
    assert cmd == ["docker", "logs", "--timestamps", "--since", "1h", "api"]
    assert kw["stderr"] == subprocess.STDOUT


@pytest.mark.parametrize("installed,expected", [
    ({"docker", "podman"}, "docker"),
    ({"podman"}, "podman"),           # RHEL and Fedora ship podman, not docker
])
def test_container_engine_auto(monkeypatch, installed, expected):
    monkeypatch.setattr(collectors.shutil, "which", lambda name: f"/usr/bin/{name}" if name in installed else None)
    assert collectors.container_engine() == expected


def test_container_engine_missing(monkeypatch):
    monkeypatch.setattr(collectors.shutil, "which", lambda name: None)
    with pytest.raises(CollectorError, match="neither docker nor podman"):
        collectors.container_engine()


def test_podman_uses_the_same_flags(calls):
    collectors.from_docker("api", "1h", engine="podman")
    assert calls[0][0] == ["podman", "logs", "--timestamps", "--since", "1h", "api"]


def test_journal_without_permission_is_an_error(monkeypatch):
    hint = ("Hint: You are currently not seeing messages from other users and the system.\n"
            "      Users in groups 'adm', 'systemd-journal', 'wheel' can see all messages.\n")
    monkeypatch.setattr(collectors.subprocess, "run",
                        lambda cmd, **kw: FakeProc(stdout="-- No entries --\n", stderr=hint))
    with pytest.raises(CollectorError, match="may not read the system journal"):
        collectors.from_journal("nginx")


def test_journal_entries_with_a_hint_are_kept(monkeypatch):
    line = "2026-11-16T10:00:00+0000 host app[1]: ERROR x\n"
    monkeypatch.setattr(collectors.subprocess, "run",
                        lambda cmd, **kw: FakeProc(stdout=line, stderr="Hint: You are currently not seeing messages"))
    assert collectors.from_journal("app") == line


def test_unreadable_file_says_how_to_fix_it(tmp_path, monkeypatch):
    import builtins
    import errno

    path = tmp_path / "messages"
    path.write_text("x\n")
    real_open = builtins.open

    def denied(file, *a, **kw):
        if str(file) == str(path):
            raise PermissionError(errno.EACCES, "Permission denied", str(file))
        return real_open(file, *a, **kw)

    monkeypatch.setattr(builtins, "open", denied)
    with pytest.raises(CollectorError, match="try sudo"):
        collectors.from_file(str(path))


def test_k8s_pod_command(calls):
    collectors.from_k8s(pod="deploy/api", namespace="prod", since="15m", previous=True)
    cmd = calls[0][0]
    assert cmd[:2] == ["kubectl", "logs"]
    assert "--since=15m" in cmd and "deploy/api" in cmd and "--previous" in cmd
    assert cmd[cmd.index("-n") + 1] == "prod"
    assert "--all-containers=true" in cmd


def test_k8s_selector_and_container(calls):
    collectors.from_k8s(selector="app=api", container="app", context="staging")
    cmd = calls[0][0]
    assert cmd[1:3] == ["--context", "staging"]
    assert cmd[cmd.index("-l") + 1] == "app=api" and cmd[cmd.index("-c") + 1] == "app"
    assert "--all-containers=true" not in cmd


def test_k8s_needs_exactly_one_target():
    with pytest.raises(CollectorError):
        collectors.from_k8s()
    with pytest.raises(CollectorError):
        collectors.from_k8s(pod="a", selector="b=c")


@pytest.mark.parametrize("call", [
    lambda: collectors.from_journal("--output=json", "1h"),
    lambda: collectors.from_docker("-f", "1h"),
    lambda: collectors.from_k8s(pod="--kubeconfig=/tmp/x"),
    lambda: collectors.from_journal("", "1h"),
])
def test_option_like_arguments_are_rejected(call, calls):
    with pytest.raises(CollectorError):
        call()
    assert calls == []


def test_missing_binary(monkeypatch):
    def boom(cmd, **kw):
        raise FileNotFoundError(cmd[0])
    monkeypatch.setattr(collectors.subprocess, "run", boom)
    with pytest.raises(CollectorError, match="not found on PATH"):
        collectors.from_journal("nginx")


def test_timeout(monkeypatch):
    def slow(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw["timeout"])
    monkeypatch.setattr(collectors.subprocess, "run", slow)
    with pytest.raises(CollectorError, match="did not finish"):
        collectors.from_docker("api", timeout=1)


def test_nonzero_exit_reports_last_stderr_line(monkeypatch):
    monkeypatch.setattr(collectors.subprocess, "run",
                        lambda cmd, **kw: FakeProc(stderr="warn\nNo such unit\n", returncode=1))
    with pytest.raises(CollectorError, match="exited 1: No such unit"):
        collectors.from_journal("nope")


def test_file_plain_gz_and_missing(tmp_path):
    plain = tmp_path / "a.log"
    plain.write_text("one\ntwo\n")
    assert collectors.from_file(str(plain)) == "one\ntwo\n"
    gz = tmp_path / "a.log.gz"
    with gzip.open(gz, "wt") as fh:
        fh.write("zipped\n")
    assert collectors.from_file(str(gz)) == "zipped\n"
    with pytest.raises(CollectorError, match="cannot read"):
        collectors.from_file(str(tmp_path / "missing.log"))


def test_file_reads_only_the_tail_of_large_files(tmp_path):
    big = tmp_path / "big.log"
    big.write_text("".join(f"line {i:05d}\n" for i in range(1000)))
    out = collectors.from_file(str(big), max_bytes=100)
    assert out.endswith("line 00999\n") and len(out) <= 100
    assert all(len(ln) == 10 for ln in out.splitlines())


def test_tail_bytes_cuts_on_line_boundary():
    text, truncated = collectors.tail_bytes("aaaa\nbbbb\ncccc\n", 8)
    assert (text, truncated) == ("cccc\n", True)
    assert collectors.tail_bytes("short\n", 100) == ("short\n", False)


def test_join_sources():
    assert collectors.join_sources([("a", "x\n"), ("b", "y")]) == "=== SOURCE: a ===\nx\n\n=== SOURCE: b ===\ny\n\n"


def test_file_with_crlf_line_endings(tmp_path):
    f = tmp_path / "win.log"
    f.write_bytes(b"ERROR one\r\nERROR two\r\n")
    assert collectors.from_file(str(f)) == "ERROR one\nERROR two\n"
