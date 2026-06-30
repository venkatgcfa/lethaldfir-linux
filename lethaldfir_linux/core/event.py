"""
core.event
==========

Unified data model used by every parser.

Two primary record types are emitted:

  * TimelineEvent - a point-in-time event suitable for the super-timeline.
  * Finding       - a detection / suspicious observation with severity.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


# ----------------------------------------------------------------------------
# Severity levels for findings
# ----------------------------------------------------------------------------
SEV_INFO     = "INFO"
SEV_LOW      = "LOW"
SEV_MEDIUM   = "MEDIUM"
SEV_HIGH     = "HIGH"
SEV_CRITICAL = "CRITICAL"

SEV_ORDER = {SEV_INFO: 0, SEV_LOW: 1, SEV_MEDIUM: 2, SEV_HIGH: 3, SEV_CRITICAL: 4}


@dataclass
class TimelineEvent:
    """One event in the super-timeline.

    Attributes
    ----------
    timestamp : datetime
        Timezone-aware UTC datetime of the event. Naive datetimes are
        promoted to UTC at construction.
    source : str
        High-level artifact source (e.g. "auth.log", "wtmp", "dpkg.log").
    event_type : str
        Short event category (e.g. "ssh_login", "sudo", "package_install").
    user : str | None
        Subject user, if applicable.
    host : str | None
        Host the event refers to.
    description : str
        Human-readable summary of the event.
    raw : str | None
        Original raw line / record.
    metadata : dict
        Free-form structured fields (rhost, command, package, etc.).
    """

    timestamp: datetime
    source: str
    event_type: str
    description: str
    user: str | None = None
    host: str | None = None
    raw: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.astimezone(timezone.utc).isoformat()
        return d


@dataclass
class Finding:
    """A detection / suspicious observation."""

    severity: str                           # SEV_* constant
    category: str                           # e.g. "persistence", "credential"
    title: str                              # one-line summary
    description: str                        # full description
    artifact: str                           # source artifact / file path
    evidence: list[str] = field(default_factory=list)
    timestamp: datetime | None = None       # if event-bound
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Promote naive timestamps to UTC (matching TimelineEvent). Without
        # this, report writers call .astimezone(UTC) on a naive value, which
        # assumes the analyst's LOCAL tz and silently shifts the time.
        if self.timestamp is not None and self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.timestamp is not None:
            d["timestamp"] = self.timestamp.astimezone(timezone.utc).isoformat()
        return d
