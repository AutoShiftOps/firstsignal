"""Group multi-line log events: Java, Python, Go and Node stack traces become one event.

A stack trace counted line by line inflates counts and hides the real message. Lines that
continue an event (indented frames, "Caused by:", a Python traceback and its final exception
line, a Go panic and its goroutines) are attached to the line that started the event.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .parsing import TS_RE

MAX_EVENT_LINES = 200   # a runaway "continuation" is split rather than swallowing the log

_K8S_PREFIX = re.compile(r"^\[[^\]\s]+\] ")
_CAUSE = re.compile(r"^\s*(?:Caused by:|Suppressed:)")
_PY_TRACEBACK = re.compile(r"^Traceback \(most recent call last\):")
_PY_CHAIN = re.compile(r"^(?:During handling of the above exception|The above exception was the direct cause)")
_PY_EXCEPTION = re.compile(r"^[A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt|Warning|Fault)\b(?::.*)?$")
# a fully qualified Java exception on its own line, as log4j and logback print it after the message
_JAVA_EXCEPTION = re.compile(r"^(?:[a-z][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error|Throwable)\b(?::.*)?$")
_GO_START = re.compile(r"^(?:panic: |fatal error: )")
_GO_CONT = re.compile(r"^(?:goroutine \d+ \[|created by |\[signal |\[recovered\]|[\w./*()\[\]-]+\(.*\)$)")
_GO_END = re.compile(r"^exit status \d+$")


@dataclass
class Event:
    """One logical event: a head line and the lines that continue it, with their line numbers."""

    lines: list[tuple[int, str]] = field(default_factory=list)

    @property
    def head(self) -> tuple[int, str]:
        return self.lines[0]

    @property
    def multiline(self) -> bool:
        return len(self.lines) > 1

    def causal_rank(self) -> dict[int, int]:
        """Order of the lines by when what they describe happened, earliest first.

        The log line that reports an exception is written after it, so it comes last. Python
        prints a chain oldest first; Java prints the outermost exception first and its deepest
        "Caused by:" last, and the deepest cause happened first.
        """
        body = self.lines[1:]
        starts = [i for i, (_, raw) in enumerate(body) if _CAUSE.match(_content(raw))]
        if starts:
            # sections: [top exception] [cause 1] ... [deepest cause]; deepest first, top last
            bounds = [0, *starts, len(body)]
            sections = [body[bounds[i]:bounds[i + 1]] for i in range(len(bounds) - 1)]
            ordered = [line for section in reversed(sections) for line in section]
        else:
            ordered = body
        rank = {no: i for i, (no, _) in enumerate(ordered)}
        rank[self.head[0]] = len(ordered)
        return rank

    def exception_line(self) -> tuple[int, str] | None:
        """The line that names the exception: Java's deepest "Caused by:", else the last exception line
        (Python's final line, or the Java exception printed after the message)."""
        for rx in (_CAUSE, _PY_EXCEPTION):
            for no, raw in reversed(self.lines[1:]):
                if rx.match(_content(raw)):
                    return no, raw
        return None


def _content(raw: str) -> str:
    """The line without a kubectl prefix or a leading docker timestamp, keeping its indentation."""
    line = _K8S_PREFIX.sub("", raw.rstrip("\r\n"), count=1)
    m = TS_RE.match(line)
    if m and line[m.end():m.end() + 1] == " ":
        line = line[m.end() + 1:]
    return line


def is_traceback_header(raw: str) -> bool:
    """Python's "Traceback (most recent call last):" line."""
    return bool(_PY_TRACEBACK.match(_content(raw)))


def is_frame(raw: str) -> bool:
    """A stack frame or traceback header: never useful as an example on its own."""
    c = _content(raw)
    return bool(c[:1].isspace() or _PY_TRACEBACK.match(c) or _GO_CONT.match(c))


class Grouper:
    """Feed lines one at a time; complete events come out. Call flush() at the end of a source."""

    def __init__(self):
        self.event: Event | None = None
        self.mode: str | None = None      # "py", "py_done", "go" while inside a trace
        self.blanks: list[tuple[int, str]] = []

    def _start(self, no: int, raw: str, mode: str | None = None) -> list[Event]:
        done = self.flush()
        self.event, self.mode = Event([(no, raw)]), mode
        return done

    def flush(self) -> list[Event]:
        done = [self.event] if self.event else []
        self.event, self.mode, self.blanks = None, None, []
        return done

    def feed(self, no: int, raw: str) -> list[Event]:
        c = _content(raw)
        if not c.strip():
            if self.event is not None and self.mode:
                self.blanks.append((no, raw))   # Python and Go traces contain blank lines
                return []
            return self.flush()
        if self.event is None:
            return self._start(no, raw, "py" if _PY_TRACEBACK.match(c) else "go" if _GO_START.match(c) else None)
        if len(self.event.lines) >= MAX_EVENT_LINES:
            return self._start(no, raw)
        if self._continues(c):
            self.event.lines += self.blanks + [(no, raw)]
            self.blanks = []
            return []
        return self._start(no, raw, "py" if _PY_TRACEBACK.match(c) else "go" if _GO_START.match(c) else None)

    def _continues(self, c: str) -> bool:
        after_blank = bool(self.blanks)
        if self.mode in ("py", "py_done"):
            if _PY_CHAIN.match(c) or _PY_TRACEBACK.match(c):
                self.mode = "py"
                return True
            if self.mode == "py" and not after_blank:
                if _PY_EXCEPTION.match(c):
                    self.mode = "py_done"
                    return True
                return c[:1].isspace()
            return False
        if self.mode == "go":
            if _GO_END.match(c):
                self.mode = None
                return True
            return bool(c[:1].isspace() or _GO_CONT.match(c))
        if after_blank:
            return False
        if _PY_TRACEBACK.match(c):
            self.mode = "py"
            return True
        if _JAVA_EXCEPTION.match(c) and len(self.event.lines) == 1:
            return True   # the exception printed right after the log message that reported it
        return bool(c[:1].isspace() or _CAUSE.match(c))
