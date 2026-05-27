"""
parsers.samba_logs
==================

Parses Samba/CIFS file server logs for auth failures and file access.

Files: /var/log/samba/log.smbd*, /var/log/samba/log.*

Findings: MEDIUM for auth failures, INFO for file access events.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_MEDIUM
from ..core.utils import read_lines
from .base import BaseParser

SAMBA_TS_RE = re.compile(
    r"\[(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
)


class SambaLogsParser(BaseParser):
    name = "samba_logs"

    def run(self) -> None:
        fail_ctr: Counter = Counter()
        for f in self.finder.find_by_glob([
            "**/var/log/samba/log.smbd*",
            "**/var/log/samba/log.*",
        ]):
            if f.is_file():
                self.note_file(f)
                self._parse(f, fail_ctr)

        for ip, n in fail_ctr.items():
            if n >= 10:
                self.emit_finding(
                    severity=SEV_MEDIUM, category="credential_access",
                    title=f"Samba auth failures from {ip}: {n}",
                    description=f"{n} Samba authentication failures from {ip}.",
                    artifact="samba logs", metadata={"ip": ip, "count": n},
                )

    def _parse(self, path: Path, fc: Counter) -> None:
        for line in read_lines(path):
            m = SAMBA_TS_RE.search(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(m["ts"].split(".")[0],
                    "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            low = line.lower()
            self.emit_event(timestamp=ts, source="samba",
                event_type="samba_event", description=line.strip()[:300],
                raw=line)
            if "authentication" in low and "failed" in low:
                ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                fc[ip_m.group(1) if ip_m else "unknown"] += 1
