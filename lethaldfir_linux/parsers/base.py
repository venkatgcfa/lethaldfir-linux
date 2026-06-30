"""
parsers.base
============

Base class every parser inherits from. Defines the parser contract
and provides convenience helpers for emitting events / findings and
recording errors.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.case import Case
from ..core.event import Finding, TimelineEvent
from ..core.finder import EvidenceFinder


class BaseParser:
    """Subclasses must define ``name`` and override :py:meth:`run`."""

    name: str = "base"

    def __init__(self, finder: EvidenceFinder, case: Case) -> None:
        self.finder = finder
        self.case = case
        self._files_seen: int = 0
        self._events: int = 0
        self._findings: int = 0
        self._errors: list[str] = []

    # ------------------------------------------------------------------
    # Subclass hook
    # ------------------------------------------------------------------
    def run(self) -> None:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Convenience emitters - track per-parser stats automatically
    # ------------------------------------------------------------------
    def emit_event(
        self,
        timestamp: datetime,
        source: str,
        event_type: str,
        description: str,
        **kw: Any,
    ) -> None:
        self.case.add_event(
            TimelineEvent(
                timestamp=timestamp,
                source=source,
                event_type=event_type,
                description=description,
                **kw,
            )
        )
        self._events += 1

    def emit_finding(
        self,
        severity: str,
        category: str,
        title: str,
        description: str,
        artifact: str,
        evidence: list[str] | None = None,
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.case.add_finding(
            Finding(
                severity=severity,
                category=category,
                title=title,
                description=description,
                artifact=artifact,
                evidence=evidence or [],
                timestamp=timestamp,
                metadata=metadata or {},
            )
        )
        self._findings += 1

    def note_file(self, path: Path) -> None:
        self._files_seen += 1

    def note_error(self, msg: str) -> None:
        self._errors.append(msg)

    # ------------------------------------------------------------------
    # Per-parser CSV output
    # ------------------------------------------------------------------
    def write_csv(
        self,
        filename: str,
        records: list[dict],
        fieldnames: list[str],
    ) -> Path | None:
        """Write parser-specific CSV to the output csv/ directory.

        Returns the path written, or None if output_dir is not set.
        """
        if not self.case.output_dir or not records:
            return None
        csv_dir = self.case.output_dir / "csv"
        csv_dir.mkdir(parents=True, exist_ok=True)
        path = csv_dir / filename
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=fieldnames, extrasaction="ignore"
            )
            writer.writeheader()
            for rec in records:
                writer.writerow(rec)
        return path

    def finalize(self) -> None:
        self.case.record_stats(
            parser_name=self.name,
            files=self._files_seen,
            events=self._events,
            findings=self._findings,
            errors=self._errors,
        )

