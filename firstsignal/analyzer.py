"""Pattern matching, Four Golden Signal mapping and severity scoring."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .grouping import Event, Grouper, is_frame
from .parsing import LEVEL_RANK, TS_RE, parse_line, to_datetime
from .patterns import DEFAULT_NOISE, SEVERITY_RANK, SIGNALS, Pattern
from .redact import Redactor

_SOURCE_MARK = re.compile(r"^=== SOURCE: (.+) ===$")
_NORMALIZERS = [
    (TS_RE, "<TS>"),
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TS>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE), "<UUID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b(?=[0-9a-f]*\d)[0-9a-f]{8,}\b", re.IGNORECASE), "<ID>"),
    (re.compile(r"\b\d+(?:\.\d+)?(ms|s|m|h|kb|mb|gb|%)\b", re.IGNORECASE), r"<N>\1"),
    (re.compile(r"\b\d{4,}\b"), "<N>"),
]


@dataclass
class Finding:
    """All matches of one pattern."""

    key: str
    title: str
    signal: str
    severity: str
    advice: str
    count: int = 0
    first_index: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    examples: list[str] = field(default_factory=list)
    # set only when analyze(track_locations=True): "file:line" for the first match and each example
    first_location: str | None = None
    locations: list[str] = field(default_factory=list)
    earliest: str | None = None   # the earliest timestamp among all matches, not just the first line


@dataclass
class Analysis:
    """Result of analyzing one log stream."""

    findings: dict[str, Finding]
    signals: dict[str, list[str]]
    order: list[str]
    top_lines: list[tuple[int, str]]
    stats: dict
    severity: str


def normalize_line(line: str) -> str:
    """Collapse the variable parts of a line so repeats group together."""
    line = line.strip()
    for rx, repl in _NORMALIZERS:
        line = rx.sub(repl, line)
    return line


def parse_ts(ts: str | None) -> datetime | None:
    """Parse a log timestamp (ISO, nginx, syslog, Apache or epoch); None if it cannot be compared."""
    return to_datetime(ts)


def analyze(
    text: str,
    patterns: list[Pattern],
    noise=None,
    redactor: Redactor | None = None,
    max_examples: int = 3,
    top_n: int = 10,
    track_locations: bool = False,
    line_offsets: dict[str, int] | None = None,
) -> Analysis:
    """Analyze log text against patterns. Pure function: no I/O, no side effects.

    With track_locations, each finding records "source:line" for its first match and examples.
    line_offsets gives, per source, how many lines were dropped before the text starts.
    """
    noise = DEFAULT_NOISE if noise is None else noise
    redactor = redactor or Redactor()
    text = redactor.mask_blocks(text)  # multi-line secrets must go before the text is split
    findings: dict[str, Finding] = {}
    repeats: Counter = Counter()
    levels: Counter = Counter()
    sources: list[str] = []
    total = filtered = matched_lines = structured = 0
    first_ts = last_ts = None
    line_offsets = line_offsets or {}
    source, line_no = None, 0
    earliest: dict[str, datetime] = {}

    events = 0
    multiline = 0

    def handle(ev_group: Event) -> None:
        nonlocal total, filtered, matched_lines, structured, first_ts, last_ts, events, multiline
        head_no, head_raw = ev_group.head
        n_lines = sum(1 for _, r in ev_group.lines if r.strip())
        total += n_lines
        events += 1
        multiline += ev_group.multiline
        ev = parse_line(head_raw, events)
        # health checks are noise unless they are themselves reporting a failure
        if LEVEL_RANK[ev.level] < LEVEL_RANK["error"] and any(rx.search(ev.raw) for rx in noise):
            filtered += n_lines
            return
        levels[ev.level] += 1
        structured += ev.structured
        if ev.timestamp:
            first_ts = first_ts or ev.timestamp
            last_ts = ev.timestamp
        if ev.level == "debug":
            return
        # what each pattern is matched against: the head's parsed text, then every continuation line
        texts = [(head_no, head_raw, ev.text)] + [(no, raw, raw.strip()) for no, raw in ev_group.lines[1:]]
        exc = ev_group.exception_line() if ev_group.multiline else None
        hit = False
        for pat in patterns:
            match = next(((no, raw) for no, raw, t in texts if t and pat.regex.search(t)), None)
            if match is None:
                continue
            hit = True
            f = findings.get(pat.key)
            if f is None:
                f = findings[pat.key] = Finding(
                    pat.key, pat.title, pat.signal, pat.severity, pat.advice,
                    first_index=ev.index, first_seen=ev.timestamp,
                )
            f.count += 1
            f.last_seen = ev.timestamp or f.last_seen
            shown = match
            if ev_group.multiline and exc and (match[0] == head_no or is_frame(match[1])):
                shown = exc            # the exception's type and message, not a frame
            where_no = shown[0]
            where = f"{source}:{where_no}" if source else f"line {where_no}"
            if track_locations and f.first_location is None:
                f.first_location = where
            if len(f.examples) < max_examples:
                example = head_raw.strip()
                if shown[0] != head_no:
                    example = f"{example} ⏎ {shown[1].strip()}"
                f.examples.append(redactor(example)[:300])
                if track_locations:
                    f.locations.append(where)
            when = parse_ts(ev.timestamp)
            if when is not None:
                prev = earliest.get(pat.key)
                try:
                    if prev is None or when < prev:
                        earliest[pat.key] = when
                        f.earliest = ev.timestamp
                except TypeError:  # naive and aware timestamps cannot be compared
                    pass
        matched_lines += n_lines if hit else 0
        if hit or LEVEL_RANK[ev.level] >= LEVEL_RANK["unknown"]:
            repeats[normalize_line(redactor(ev.text))[:240]] += 1

    grouper = Grouper()
    for raw in text.splitlines():
        mark = _SOURCE_MARK.match(raw.strip())
        if mark:
            for done in grouper.flush():
                handle(done)
            sources.append(mark.group(1))
            source = mark.group(1)
            line_no = line_offsets.get(source, 0)
            continue
        line_no += 1
        for done in grouper.feed(line_no, raw):
            handle(done)
    for done in grouper.flush():
        handle(done)

    order = sorted(findings, key=lambda k: findings[k].first_index)
    ranked = sorted(findings.values(), key=lambda f: (-SEVERITY_RANK[f.severity], -f.count))
    signals = {
        sig: [f.key for f in ranked if f.signal == sig]
        for sig in SIGNALS
        if any(f.signal == sig for f in ranked)
    }
    severity = ranked[0].severity if ranked else "none"
    stats = {
        "lines_total": total,
        "lines_noise_filtered": filtered,
        "lines_analyzed": total - filtered,
        "lines_matched": matched_lines,
        "lines_structured": structured,
        "events": events,
        "multiline_events": multiline,
        "levels": dict(levels),
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "sources": sources,
    }
    return Analysis(
        findings={f.key: f for f in ranked},
        signals=signals,
        order=order,
        top_lines=[(n, msg) for msg, n in repeats.most_common(top_n)],
        stats=stats,
        severity=severity,
    )


def _utc(when: datetime) -> tuple[datetime, bool]:
    """Make a timestamp comparable. Naive times are taken as UTC; the flag says that happened."""
    if when.tzinfo is None:
        return when.replace(tzinfo=timezone.utc), True
    return when, False


def time_order(analysis: Analysis) -> tuple[list[str], dict]:
    """Findings ordered by their earliest timestamp; findings without one follow in text order.

    Across several files, text order is not time order, so bundles use this ordering.
    Returns (order, info) where info says how many findings had no timestamp and whether
    any time without a zone was taken as UTC.
    """
    timed, untimed, assumed = [], [], False
    for key in analysis.order:
        when = parse_ts(analysis.findings[key].earliest)
        if when is None:
            untimed.append(key)
            continue
        when, naive = _utc(when)
        assumed |= naive
        timed.append((when, key))
    timed.sort(key=lambda t: t[0])
    return [k for _, k in timed] + untimed, {"untimed": len(untimed), "assumed_utc": assumed,
                                              "basis": "timestamp" if timed else "position"}


def earliest_finding(analysis: Analysis) -> tuple[str | None, dict]:
    """The finding seen first in time, with how that was decided (see time_order)."""
    if not analysis.findings:
        return None, {"basis": "none", "untimed": 0, "assumed_utc": False}
    order, info = time_order(analysis)
    return order[0], info
