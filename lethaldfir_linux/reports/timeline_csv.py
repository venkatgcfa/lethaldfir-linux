"""
reports.timeline_csv
====================

Writes ``timeline.csv`` — the super-timeline. Each TimelineEvent becomes
one row. Sorted ascending by timestamp.

Column layout is intentionally close to the well-known plaso/log2timeline
"l2tcsv" schema so it can be loaded straight into Timeline Explorer or
Excel pivot tables.
"""

from __future__ import annotations

import csv
import json
from datetime import timezone
from pathlib import Path

from ..core.utils import neutralize_formula as _nf


FIELDS = [
    "datetime_utc",
    "date",
    "time",
    "source",
    "event_type",
    "user",
    "host",
    "description",
    "metadata",
    "raw",
]


def write_timeline_csv(case, path) -> Path:
    path = Path(path)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        for ev in case.sorted_events():
            ts = ev.timestamp.astimezone(timezone.utc)
            row = {
                "datetime_utc": ts.isoformat(),
                "date":         ts.strftime("%Y-%m-%d"),
                "time":         ts.strftime("%H:%M:%S"),
                "source":       ev.source,
                "event_type":   ev.event_type,
                "user":         ev.user or "",
                "host":         ev.host or "",
                "description":  ev.description,
                "metadata":     json.dumps(ev.metadata, default=str) if ev.metadata else "",
                "raw":          (ev.raw or "")[:2000],
            }
            writer.writerow({k: _nf(v) for k, v in row.items()})
    return path
