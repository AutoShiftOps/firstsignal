"""Incident memory: remember what each incident looked like, and recognize it next time.

Only the shape of an incident is stored: which patterns fired, in what order, how often,
on which target, plus a note you write. No log lines are kept.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .analyzer import Analysis
from .patterns import SEVERITY_RANK

SAME_INCIDENT_WINDOW = timedelta(minutes=60)
CLOCK_SKEW = timedelta(minutes=5)   # a re-run may look slightly earlier than the last one, no more
MATCH_THRESHOLD = 0.6
LOCK_TIMEOUT = 10.0                 # seconds to wait for another firstsignal run to finish writing
_FIRST_WEIGHT = 0.2


@dataclass
class Incident:
    """One remembered incident."""

    id: str
    recorded_at: str
    last_seen_at: str
    target: str
    source: str
    severity: str
    keys: list[str]
    first: str | None
    counts: dict[str, int] = field(default_factory=dict)
    runs: int = 1
    note: str = ""


@dataclass
class Match:
    """A past incident that resembles the current one."""

    incident: Incident
    similarity: float
    days_ago: int


def default_path() -> Path:
    """Where history lives: $FIRSTSIGNAL_HISTORY, or ~/.firstsignal/history.jsonl."""
    env = os.environ.get("FIRSTSIGNAL_HISTORY")
    return Path(env) if env else Path.home() / ".firstsignal" / "history.jsonl"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: str) -> datetime:
    """Parse a stored timestamp. Times without a zone are taken as UTC. Raises ValueError."""
    when = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def from_analysis(analysis: Analysis, target: str, source: str, now: datetime | None = None) -> Incident:
    """Reduce an analysis to its fingerprint."""
    now = now or _now()
    keys = sorted(analysis.findings)
    stamp = now.isoformat(timespec="seconds")
    return Incident(
        id=secrets.token_hex(4), recorded_at=stamp, last_seen_at=stamp, target=target, source=source,
        severity=analysis.severity, keys=keys, first=analysis.order[0] if analysis.order else None,
        counts={k: f.count for k, f in analysis.findings.items()},
    )


def similarity(a: Incident, b: Incident) -> float:
    """0..1. Mostly overlap of the patterns that fired, plus a bonus when the same one came first."""
    sa, sb = set(a.keys), set(b.keys)
    if not sa or not sb:
        return 0.0
    jaccard = len(sa & sb) / len(sa | sb)
    same_first = a.first is not None and a.first == b.first
    return round(jaccard * (1 - _FIRST_WEIGHT) + (_FIRST_WEIGHT if same_first else 0.0), 3)


@dataclass
class History:
    """What was read from the history file. Lines that could not be read are kept as they were."""

    incidents: list[Incident] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)


def _valid(inc: Incident) -> Incident:
    """Check and normalize timestamps. Raises ValueError for a record that cannot be compared."""
    for name in ("recorded_at", "last_seen_at"):
        setattr(inc, name, _parse(getattr(inc, name)).isoformat(timespec="seconds"))
    if not isinstance(inc.keys, list) or not isinstance(inc.counts, dict):
        raise ValueError("bad record shape")
    return inc


def read(path: Path) -> History:
    """Read history. Unreadable lines are set aside, never fatal, and never lost on the next save."""
    out = History()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        if not line.strip():
            continue
        try:
            out.incidents.append(_valid(Incident(**json.loads(line))))
        except (ValueError, TypeError, AttributeError):
            out.unreadable.append(line)
    return out


def load(path: Path) -> list[Incident]:
    """Read the incidents in history (unreadable lines are skipped)."""
    return read(path).incidents


def save(path: Path, incidents: list[Incident], unreadable: list[str] | None = None) -> None:
    """Write history atomically, private to the current user. Unreadable lines are written back as they were."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for line in unreadable or []:
                fh.write(line + "\n")
            for inc in incidents:
                fh.write(json.dumps(asdict(inc), ensure_ascii=False) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


@contextlib.contextmanager
def locked(path: Path):
    """Hold an exclusive lock on the history file while reading, changing and writing it,
    so two runs at once cannot overwrite each other's record."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + LOCK_TIMEOUT
    try:
        while True:
            try:
                _lock(fd)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise OSError(f"history file is busy: {path}") from None
                time.sleep(0.05)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)


if os.name == "nt":  # pragma: no cover - exercised on the Windows CI runners
    import msvcrt

    def _lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


def _same_incident(old: Incident, new: Incident) -> bool:
    """A re-run during the same incident: same target, within the window, and the findings overlap.

    The patterns may grow or shrink between runs (a new symptom appears), so identity is not the
    exact set of patterns. A last_seen_at in the future beyond normal clock skew never matches,
    so one bad timestamp cannot absorb every later run.
    """
    if old.target != new.target:
        return False
    gap = _parse(new.recorded_at) - _parse(old.last_seen_at)
    if not -CLOCK_SKEW <= gap <= SAME_INCIDENT_WINDOW:
        return False
    a, b = set(old.keys), set(new.keys)
    return bool(a & b) and (a <= b or b <= a or similarity(old, new) >= MATCH_THRESHOLD)


def _merge(ongoing: Incident, current: Incident) -> None:
    """Fold a re-run into the incident it belongs to. Nothing seen earlier is lost."""
    if _parse(current.recorded_at) > _parse(ongoing.last_seen_at):
        ongoing.last_seen_at = current.recorded_at
    ongoing.runs += 1
    ongoing.keys = sorted(set(ongoing.keys) | set(current.keys))
    for key, n in current.counts.items():
        ongoing.counts[key] = max(n, ongoing.counts.get(key, 0))
    if SEVERITY_RANK.get(current.severity, 0) > SEVERITY_RANK.get(ongoing.severity, 0):
        ongoing.severity = current.severity
    ongoing.first = ongoing.first or current.first   # what came first stays first


def remember(path: Path, current: Incident, limit: int = 3) -> tuple[Incident, list[Match]]:
    """Find similar past incidents, then record this one.

    Re-running during the same incident updates the existing record instead of adding one,
    and that record is never reported as a past match.
    """
    with locked(path):
        stored = read(path)
        history = stored.incidents
        ongoing = next((h for h in reversed(history) if _same_incident(h, current)), None)
        matches = _similar(current, history, skip=ongoing, now=current.recorded_at)
        if ongoing is not None:
            _merge(ongoing, current)
            recorded = ongoing
        else:
            while any(h.id == current.id for h in history):
                current.id = secrets.token_hex(4)
            history.append(current)
            recorded = current
        save(path, history, stored.unreadable)
    return recorded, matches[:limit]


def _similar(me: Incident, history: list[Incident], skip=None, now: str | None = None) -> list[Match]:
    """Past incidents that resemble `me`, best first."""
    ref = _parse(now or me.last_seen_at)
    out = []
    for past in history:
        if past is skip or past.id == me.id:
            continue
        score = similarity(me, past)
        if score >= MATCH_THRESHOLD:
            out.append(Match(past, score, max(0, (ref - _parse(past.last_seen_at)).days)))
    out.sort(key=lambda m: (-m.similarity, m.days_ago))
    return out


def find_similar(path: Path, incident_id: str, limit: int = 3) -> list[Match]:
    """Past incidents similar to the stored incident with this id."""
    history = load(path)
    me = next((h for h in history if h.id == incident_id), None)
    return [] if me is None else _similar(me, history)[:limit]


def upsert(path: Path, incident: Incident, limit: int = 3) -> list[Match]:
    """Create or replace one incident by id (used by watch) and return similar past incidents.

    A note already attached to the stored record is kept.
    """
    with locked(path):
        stored = read(path)
        history = stored.incidents
        matches = _similar(incident, history)
        for i, past in enumerate(history):
            if past.id == incident.id:
                incident.note = past.note
                history[i] = incident
                break
        else:
            history.append(incident)
        save(path, history, stored.unreadable)
    return matches[:limit]


def set_note(path: Path, incident_id: str, note: str) -> Incident | None:
    """Attach what fixed it. Returns the incident, or None if the id is unknown."""
    with locked(path):
        stored = read(path)
        hit = next((h for h in stored.incidents if h.id == incident_id), None)
        if hit is None:
            return None
        hit.note = note.strip()
        save(path, stored.incidents, stored.unreadable)
    return hit


def forget(path: Path, incident_id: str) -> bool:
    """Remove one incident. Returns False if the id is unknown."""
    with locked(path):
        stored = read(path)
        kept = [h for h in stored.incidents if h.id != incident_id]
        if len(kept) == len(stored.incidents):
            return False
        save(path, kept, stored.unreadable)
    return True


def matches_as_dicts(matches: list[Match]) -> list[dict]:
    """Shape matches for the JSON report."""
    return [
        {"id": m.incident.id, "last_seen_at": m.incident.last_seen_at, "days_ago": m.days_ago,
         "target": m.incident.target, "severity": m.incident.severity, "similarity": m.similarity,
         "first": m.incident.first, "note": m.incident.note}
        for m in matches
    ]
