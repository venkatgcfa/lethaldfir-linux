"""
core.case
=========

The Case is the central in-memory container for everything an analysis
run produces. Each parser receives the Case and pushes events / findings
into it. Reports read from it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .event import Finding, TimelineEvent, SEV_ORDER


class Case:
    """In-memory case container."""

    def __init__(
        self,
        evidence_root: Path,
        case_name: str = "case",
        output_dir: Path | None = None,
        verbose: bool = False,
    ) -> None:
        self.evidence_root: Path = evidence_root
        self.case_name: str = case_name
        self.output_dir: Path | None = output_dir
        self.verbose: bool = verbose
        self.created_at: datetime = datetime.now(timezone.utc)

        self.events: list[TimelineEvent] = []
        self.findings: list[Finding] = []

        # parser_name -> arbitrary structured artifact data
        self.artifacts: dict[str, Any] = {}

        # parser_name -> { "files": int, "events": int, "findings": int,
        #                  "errors": list[str] }
        self.stats: dict[str, dict[str, Any]] = {}

        # detected host metadata (filled by parsers)
        self.host_info: dict[str, Any] = {
            "hostname": None,
            "os_release": None,
            "kernel": None,
            "distro": None,
        }

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------
    def add_event(self, event: TimelineEvent) -> None:
        self.events.append(event)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def set_artifact(self, name: str, data: Any) -> None:
        self.artifacts[name] = data

    def record_stats(
        self,
        parser_name: str,
        files: int = 0,
        events: int = 0,
        findings: int = 0,
        errors: list[str] | None = None,
    ) -> None:
        prev = self.stats.get(
            parser_name,
            {"files": 0, "events": 0, "findings": 0, "errors": []},
        )
        prev["files"]    += files
        prev["events"]   += events
        prev["findings"] += findings
        if errors:
            prev["errors"].extend(errors)
        self.stats[parser_name] = prev

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------
    def sorted_events(self) -> list[TimelineEvent]:
        return sorted(self.events, key=lambda e: e.timestamp)

    def findings_sorted(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.category, f.title),
        )

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def to_json_dict(self) -> dict[str, Any]:
        return {
            "case_name": self.case_name,
            "created_at": self.created_at.isoformat(),
            "evidence_root": str(self.evidence_root),
            "host_info": self.host_info,
            "stats": self.stats,
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings_sorted()],
            "events": [e.to_dict() for e in self.sorted_events()],
            "artifacts": self.artifacts,
        }

    def write_json(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_json_dict(), indent=2, default=str))
