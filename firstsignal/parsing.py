"""Turn raw log lines into events: plain text, JSON lines, kubectl/docker prefixes."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2}| ?UTC\b)?")
# Other common shapes. Each is tried only if the ISO form is absent.
_SLASH_TS = re.compile(r"\b\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?")          # nginx error log, Go log
_CLF_TS = re.compile(r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")  # Apache / nginx access
_SYSLOG_TS = re.compile(r"^(?:<\d+>)?([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2})\b")      # syslog, journalctl default
_ISO_PARTS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?"
                        r"\s*(Z|UTC|[+-]\d{2}:?\d{2})?$")
_EPOCH = re.compile(r"^\d{10}(?:\d{3})?(?:\.\d+)?$")                                    # JSON ts in seconds or ms
_K8S_PREFIX_RE = re.compile(r"^\[[^\]\s]+\]\s+")
_LEVEL_KV_RE = re.compile(r"\b(?:level|lvl|severity)=\"?([A-Za-z]+)")
_LEVEL_BRACKET_RE = re.compile(r"\[(emerg|alert|crit|error|warn|notice|info|debug)\]")
_LEVEL_WORD_RE = re.compile(r"\b(TRACE|DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|ERR|CRITICAL|CRIT|FATAL|PANIC)\b")

_LEVELS = {
    "trace": "debug", "debug": "debug",
    "info": "info", "notice": "info", "information": "info",
    "warn": "warn", "warning": "warn",
    "err": "error", "error": "error",
    "crit": "fatal", "critical": "fatal", "fatal": "fatal", "panic": "fatal",
    "emerg": "fatal", "alert": "fatal",
}
LEVEL_RANK = {"debug": 0, "info": 1, "unknown": 2, "warn": 3, "error": 4, "fatal": 5}

_MSG_KEYS = ("msg", "message", "log", "event", "text")
_ERR_KEYS = ("error", "err", "exception", "exc_info", "stack", "stacktrace", "reason")
_LEVEL_KEYS = ("level", "severity", "lvl", "levelname", "log.level")
_TS_KEYS = ("ts", "time", "timestamp", "@timestamp", "datetime")
_STATUS_KEYS = ("status", "status_code", "statusCode", "http_status")


@dataclass
class LogEvent:
    """One parsed log line."""

    index: int
    raw: str
    text: str
    level: str = "unknown"
    timestamp: str | None = None
    structured: bool = False


def normalize_level(value) -> str:
    """Map a level name or numeric level onto debug/info/warn/error/fatal/unknown."""
    if isinstance(value, bool) or value is None:
        return "unknown"
    if isinstance(value, (int, float)):
        # pino (10..60) and Python logging (10..50) share this scale closely enough
        if value <= 20:
            return "debug"
        if value < 40:
            return "info"
        if value < 50:
            return "warn"
        if value < 60:
            return "error"
        return "fatal"
    return _LEVELS.get(str(value).strip().lower(), "unknown")


def _plain_level(line: str) -> str:
    for rx in (_LEVEL_KV_RE, _LEVEL_BRACKET_RE, _LEVEL_WORD_RE):
        m = rx.search(line)
        if m:
            level = normalize_level(m.group(1))
            if level != "unknown":
                return level
    return "unknown"


def _first(obj: dict, keys):
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    return None


def _from_json(obj: dict) -> tuple[str, str, str | None]:
    parts = []
    msg = _first(obj, _MSG_KEYS)
    if msg is not None:
        parts.append(msg if isinstance(msg, str) else json.dumps(msg))
    for key in _ERR_KEYS:
        val = obj.get(key)
        if val:
            parts.append(val if isinstance(val, str) else json.dumps(val))
    status = _first(obj, _STATUS_KEYS)
    if isinstance(status, (int, str)) and str(status).isdigit():
        parts.append(f"status={status}")
    if not parts:
        parts.append(json.dumps(obj, separators=(",", ":")))
    ts = _first(obj, _TS_KEYS)
    return " ".join(parts), normalize_level(_first(obj, _LEVEL_KEYS)), (str(ts) if ts is not None else None)


def _other_ts(line: str) -> str | None:
    """Find a non-ISO timestamp: syslog at the start of the line, nginx/Go or Apache anywhere."""
    for rx in (_SYSLOG_TS, _CLF_TS):
        m = rx.search(line)
        if m:
            return m.group(1)
    m = _SLASH_TS.search(line)
    return m.group(0) if m else None


def _iso(text: str) -> datetime:
    """ISO-like timestamps on every supported Python (3.10's fromisoformat is strict about fractions and zones)."""
    m = _ISO_PARTS.match(text)
    if not m:
        raise ValueError(text)
    y, mo, d, h, mi, sec, frac, zone = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    tz = None
    if zone in ("Z", "UTC"):
        tz = timezone.utc
    elif zone:
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    return datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec), micro, tzinfo=tz)


def to_datetime(ts, now: datetime | None = None) -> datetime | None:
    """Turn a timestamp found in a log into a datetime, or None if it is not one we understand.

    Times without a zone come back naive. Syslog times have no year: the current year is used,
    or last year when that would put the line more than a day in the future.
    """
    if ts is None:
        return None
    text = str(ts).strip()
    try:
        if _EPOCH.match(text):
            value = float(text)
            return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc)
        if "/" in text and ":" in text and text[2:3] == "/":       # 14/Nov/2026:09:41:25 +0000
            return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
        if text[4:5] == "/":                                        # 2026/11/14 09:41:25
            return _iso(text.replace("/", "-"))
        if text[:3].isalpha():                                      # Nov 14 09:41:25
            now = now or datetime.now()
            when = datetime.strptime(f"{now.year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")
            if when > now.replace(tzinfo=None) + timedelta(days=1):
                when = when.replace(year=now.year - 1)
            return when
        return _iso(text)
    except (ValueError, OverflowError, OSError):
        return None


def parse_line(raw: str, index: int = 0) -> LogEvent:
    """Parse one line. Never raises: anything unrecognized is treated as plain text."""
    line = raw.strip()
    body = _K8S_PREFIX_RE.sub("", line, count=1)
    ts = None
    m = TS_RE.match(body)
    if m:
        ts = m.group(0)
        body = body[m.end():].lstrip()

    if body.startswith("{") and body.endswith("}"):
        try:
            obj = json.loads(body)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            text, level, json_ts = _from_json(obj)
            return LogEvent(index, line, text, level, json_ts or ts, structured=True)

    if ts is None:
        m = TS_RE.search(line)
        ts = m.group(0) if m else _other_ts(body)
    return LogEvent(index, line, line, _plain_level(line), ts)
