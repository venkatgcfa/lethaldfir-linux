"""
parsers.nfs_exports
===================

Parses NFS export configuration for insecure exports.

Files: /etc/exports, /var/lib/nfs/etab

Findings: HIGH for world-readable exports, MEDIUM for no_root_squash.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import read_lines
from .base import BaseParser


class NfsExportsParser(BaseParser):
    name = "nfs_exports"

    def run(self) -> None:
        for f in self.finder.find_by_suffix(["/etc/exports"]):
            self.note_file(f)
            self._parse_exports(f)
        for f in self.finder.find_by_suffix(["/var/lib/nfs/etab"]):
            self.note_file(f)
            self._parse_exports(f)

    def _parse_exports(self, path: Path) -> None:
        try:
            ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            ts = datetime.now(timezone.utc)

        for line in read_lines(path):
            ls = line.strip()
            if not ls or ls.startswith("#"):
                continue

            self.emit_event(
                timestamp=ts, source="nfs_exports",
                event_type="nfs_export", description=f"NFS export: {ls}",
                metadata={"line": ls}, raw=ls,
            )

            # Check for world-accessible exports (*)
            if re.search(r"\*\(", ls) or "\t*(" in ls:
                self.emit_finding(
                    severity=SEV_HIGH, category="network_config",
                    title=f"World-accessible NFS export",
                    description=(
                        "NFS export is accessible to any host (*). "
                        "This allows arbitrary network access to the share."
                    ),
                    artifact=str(path), timestamp=ts, evidence=[ls],
                )

            # Check for no_root_squash
            if "no_root_squash" in ls.lower():
                self.emit_finding(
                    severity=SEV_MEDIUM, category="privilege_escalation",
                    title="NFS export with no_root_squash",
                    description=(
                        "NFS export uses no_root_squash, allowing remote "
                        "root users to have root access on the share. "
                        "This can be leveraged for privilege escalation."
                    ),
                    artifact=str(path), timestamp=ts, evidence=[ls],
                )

            # Check for sensitive paths
            export_path = ls.split()[0] if ls.split() else ""
            sensitive = ("/", "/etc", "/root", "/home", "/var")
            if export_path in sensitive:
                self.emit_finding(
                    severity=SEV_HIGH, category="network_config",
                    title=f"Sensitive path exported via NFS: {export_path}",
                    description=(
                        f"NFS exports the sensitive path '{export_path}'. "
                        "This may expose credentials, configs, or user data."
                    ),
                    artifact=str(path), timestamp=ts, evidence=[ls],
                )
