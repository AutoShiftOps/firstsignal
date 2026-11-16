"""Read log files from a support bundle (.zip, .tar, .tar.gz, .tgz) without extracting it.

A support bundle is untrusted input. Nothing is written to disk, every member is read in
bounded chunks, and hard limits stop zip bombs, path tricks and runaway nesting.
"""

from __future__ import annotations

import fnmatch
import gzip
import io
import os
import posixpath
import stat
import tarfile
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field

from .collectors import CollectorError

CHUNK = 64 * 1024
DEFAULT_MAX_FILES = 200
DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024   # uncompressed bytes read across the whole bundle
DEFAULT_MAX_MEMBERS = 10_000                   # entries looked at, logs or not
MAX_RATIO = 500                                # uncompressed / compressed; repetitive logs reach ~300
RATIO_FLOOR = 1024 * 1024                      # tiny members may compress well; only check above 1 MB
MAX_NESTED_BYTES = 256 * 1024 * 1024           # a nested archive is held in memory, so it gets its own cap
SNIFF_BYTES = 8192
MIN_SHARE = 256 * 1024                         # never read less than this much of each log file

LOG_EXTENSIONS = {".log", ".txt", ".out", ".err", ".json", ".jsonl", ".ndjson", ".trace"}
LOG_NAME_HINTS = ("log", "syslog", "messages", "journal", "stdout", "stderr", "catalina", "dmesg", "events")
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".hprof", ".dmp", ".core", ".pcap", ".pcapng",
    ".so", ".dll", ".exe", ".bin", ".class", ".jar", ".war", ".db", ".sqlite", ".sqlite3", ".rdb", ".mdmp",
}
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")


@dataclass
class ArchiveFile:
    """One log file that was analyzed."""

    name: str
    bytes_read: int
    truncated: bool = False
    line_offset: int = 0          # lines dropped from the start when only the tail was kept


@dataclass
class ArchiveResult:
    """What was read from a bundle, and what was left out and why."""

    archive: str
    parts: list[tuple[str, str]] = field(default_factory=list)
    files: list[ArchiveFile] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    total_bytes: int = 0

    @property
    def line_offsets(self) -> dict[str, int]:
        """Lines dropped from the start of each truncated file, so citations keep real line numbers."""
        return {f.name: f.line_offset for f in self.files}


class LimitError(CollectorError):
    """A whole-bundle limit was hit; reading stops."""


class _Skip(Exception):
    """This member cannot be used; skip it with the given reason."""


class _Budget:
    """Bytes and members read so far, shared across nested archives."""

    def __init__(self, max_total: int, max_members: int):
        self.max_total, self.max_members = max_total, max_members
        self.total = self.members = 0

    def take(self, n: int) -> None:
        self.total += n
        if self.total > self.max_total:
            raise LimitError(
                f"bundle is larger than the limit of {self.max_total // (1024 * 1024)} MB uncompressed; "
                "raise --max-total-mb if you trust it")

    def count_member(self) -> None:
        self.members += 1
        if self.members > self.max_members:
            raise LimitError(f"bundle has more than {self.max_members} entries")


def is_archive(path: str) -> bool:
    return path.lower().endswith(ARCHIVE_SUFFIXES)


def _unsafe_name(name: str) -> bool:
    if any(ord(c) < 32 for c in name):
        return True  # a newline in a name could fake a source marker in the joined text
    if not name or name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
        return True
    parts = name.replace("\\", "/").split("/")
    return ".." in parts


def _classify(name: str, head: bytes, include) -> str | None:
    """Return None if this member looks like a log, otherwise the reason to skip it."""
    base = posixpath.basename(name).lower()
    if any(fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(base, pat) for pat in include):
        return "binary file" if b"\x00" in head else None
    if base == "core" or (base.startswith("core.") and base[5:].isdigit()):
        return "core dump"
    ext = posixpath.splitext(base)[1]
    if ext in BINARY_EXTENSIONS:
        return "binary file"
    if b"\x00" in head:
        return "binary file"
    if head:
        printable = sum(32 <= b < 127 or b in (9, 10, 13) or b >= 128 for b in head)
        if printable / len(head) < 0.9:
            return "binary file"
    rotated = any(p.isdigit() for p in base.split(".")[1:])  # app.log.1, app.log.2026-11-01
    if ext in LOG_EXTENSIONS or rotated or any(h in base for h in LOG_NAME_HINTS):
        return None
    return "not a log file by name (use --include to add it)"


def _read_tail(stream, max_bytes: int, budget: _Budget, ceiling: int | None = None) -> tuple[bytes, bool, int]:
    """Read a stream to the end, counting every byte, and keep only the last max_bytes.

    ceiling caps how much this one stream may produce (a gzip bomb inside the bundle).
    Returns (tail, truncated, newlines_dropped).
    """
    buf = bytearray()
    dropped_lines = read = 0
    truncated = False
    while True:
        chunk = stream.read(CHUNK)
        if not chunk:
            break
        budget.take(len(chunk))
        read += len(chunk)
        if ceiling is not None and read > ceiling:
            raise _Skip("compression ratio too high (possible zip bomb)")
        buf += chunk
        if len(buf) > 2 * max_bytes:
            cut = len(buf) - max_bytes
            dropped_lines += buf.count(b"\n", 0, cut)
            del buf[:cut]
            truncated = True
    if len(buf) > max_bytes:
        cut = len(buf) - max_bytes
        dropped_lines += buf.count(b"\n", 0, cut)
        del buf[:cut]
        truncated = True
    if truncated:
        nl = buf.find(b"\n")
        if 0 <= nl < len(buf) - 1:
            del buf[:nl + 1]  # start on a whole line
            dropped_lines += 1
    return bytes(buf), truncated, dropped_lines


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n")


class _Reader:
    def __init__(self, result: ArchiveResult, budget: _Budget, per_file: int, analysis_budget: int,
                 max_files: int, include):
        self.result, self.budget = result, budget
        self.per_file, self.analysis_left, self.max_files = per_file, analysis_budget, max_files
        self.include = tuple(include)

    def skip(self, name: str, reason: str) -> None:
        self.result.skipped.append((name, reason))

    def add(self, name: str, opener, depth: int, size: int) -> None:
        """Consider one regular member. opener() returns a fresh binary stream; size is its stored size."""
        if _unsafe_name(name):
            self.skip(name, "unsafe path")
            return
        try:
            if name.lower().endswith(ARCHIVE_SUFFIXES):
                self._nested(name, opener, depth)
            else:
                self._read_member(name, opener, size)
        except LimitError:
            raise
        except _Skip as exc:
            self.skip(name, str(exc))
        except (CollectorError, OSError, EOFError, zlib.error, zipfile.BadZipFile, tarfile.TarError):
            self.skip(name, "unreadable or corrupt")

    def _nested(self, name: str, opener, depth: int) -> None:
        if depth >= 1:
            raise _Skip("nested archive deeper than one level")
        with opener() as fh:
            data, truncated, _ = _read_tail(fh, MAX_NESTED_BYTES, self.budget)
        if truncated:
            raise _Skip(f"nested archive larger than {MAX_NESTED_BYTES // (1024 * 1024)} MB")
        self.walk(io.BytesIO(data), name, depth + 1, prefix=name + "!/")

    def _read_member(self, name: str, opener, size: int) -> None:
        gz = name.lower().endswith(".gz")
        logical = name[:-3] if gz else name
        ceiling = max(MAX_RATIO * max(size, 1), RATIO_FLOOR) if gz else None
        with opener() as raw:
            stream = gzip.GzipFile(fileobj=raw) if gz else raw
            head = stream.read(SNIFF_BYTES)
            reason = _classify(logical, head, self.include)
            if reason:
                self.skip(name, reason)
                return
            if len(self.result.files) >= self.max_files:
                self.skip(name, f"over the limit of {self.max_files} files (raise --max-files)")
                return
            if self.analysis_left <= 0:
                self.skip(name, "analysis size limit reached (raise --max-bytes)")
                return
            keep = min(self.per_file, self.analysis_left)
            data, truncated, dropped = _read_tail(_Prefixed(head, stream), keep, self.budget, ceiling)
        self.analysis_left -= len(data)
        self.result.files.append(ArchiveFile(name, len(data), truncated, dropped))
        self.result.parts.append((name, _decode(data)))

    def walk(self, fileobj, name: str, depth: int, prefix: str = "") -> None:
        """Walk one archive given as a seekable binary file object."""
        if zipfile.is_zipfile(fileobj):
            fileobj.seek(0)
            self._zip(zipfile.ZipFile(fileobj), depth, prefix)
            return
        fileobj.seek(0)
        try:
            tf = tarfile.open(fileobj=fileobj, mode="r:*")
        except tarfile.TarError as exc:
            raise CollectorError(f"{name} is not a zip or tar archive") from exc
        with tf:
            self._tar(tf, depth, prefix)

    def _share(self, names, depth: int) -> None:
        """Split the analysis budget across the log files at the top level, so one big file
        cannot crowd out the rest. Each file keeps its most recent part."""
        if depth:
            return
        n = sum(1 for name in names if _classify(name.removesuffix(".gz"), b"", self.include) is None)
        if n:
            self.per_file = min(self.per_file, max(self.analysis_left // n, MIN_SHARE))

    def _zip(self, zf: zipfile.ZipFile, depth: int, prefix: str) -> None:
        with zf:
            infos = zf.infolist()
            self._share([i.filename for i in infos if not i.is_dir()], depth)
            for info in infos:
                self.budget.count_member()
                name = prefix + info.filename
                if info.is_dir():
                    continue
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    self.skip(name, "symbolic link")
                    continue
                if info.flag_bits & 0x1:
                    self.skip(name, "encrypted")
                    continue
                if info.file_size > RATIO_FLOOR and info.file_size > MAX_RATIO * max(info.compress_size, 1):
                    self.skip(name, "compression ratio too high (possible zip bomb)")
                    continue
                self.add(name, lambda i=info: zf.open(i), depth, info.file_size)

    def _tar(self, tf: tarfile.TarFile, depth: int, prefix: str) -> None:
        members = tf.getmembers()
        self._share([m.name for m in members if m.isfile()], depth)
        for member in members:
            self.budget.count_member()
            name = prefix + member.name
            if member.isdir():
                continue
            if member.issym() or member.islnk():
                self.skip(name, "link")
                continue
            if not member.isfile():
                self.skip(name, "special file")
                continue
            self.add(name, lambda m=member: _closing(tf.extractfile(m)), depth, member.size)


class _Prefixed(io.RawIOBase):
    """A stream that replays bytes already read, then continues with the rest."""

    def __init__(self, head: bytes, rest):
        self.head, self.rest = head, rest

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        if not self.head:
            return self.rest.read(n)
        if n is None or n < 0:
            out, self.head = self.head, b""
        else:
            out, self.head = self.head[:n], self.head[n:]
        return out


class _closing:
    def __init__(self, fh):
        self.fh = fh

    def __enter__(self):
        return self.fh

    def __exit__(self, *exc):
        self.fh.close()


def read_archive(
    path: str,
    max_bytes_per_file: int,
    analysis_budget: int,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_members: int = DEFAULT_MAX_MEMBERS,
    include=(),
) -> ArchiveResult:
    """Read the log files in a support bundle. Raises CollectorError if the bundle cannot be used."""
    if not os.path.isfile(path):
        raise CollectorError(f"cannot read {path}: no such file")
    result = ArchiveResult(os.path.basename(path))
    budget = _Budget(max_total_bytes, max_members)
    reader = _Reader(result, budget, max_bytes_per_file, analysis_budget, max_files, include)
    try:
        with open(path, "rb") as fh:
            reader.walk(fh, path, depth=0)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError) as exc:
        raise CollectorError(f"cannot read {path}: {exc}") from exc
    except OSError as exc:
        raise CollectorError(f"cannot read {path}: {exc.strerror or exc}") from exc
    result.total_bytes = budget.total
    if not result.files:
        reasons = Counter(r.split(" (")[0] for _, r in result.skipped).most_common(3)
        detail = "; ".join(f"{n} {r}" for r, n in reasons)
        raise CollectorError(f"no log files found in {result.archive}" + (f" (skipped: {detail})" if detail else ""))
    return result
