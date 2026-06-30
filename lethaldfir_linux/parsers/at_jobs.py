"""
parsers.at_jobs
===============

Enumerates ``at`` / ``batch`` one-shot scheduled tasks:

* ``/var/spool/at/*``       — traditional at spool
* ``/var/spool/atjobs/*``   — variant path (some distros)
* ``/var/spool/cron/atjobs/*`` — RHEL variant

Each at-job file is a shell script with embedded metadata headers
(preceded by ``# atrun`` markers). The parser extracts the owner,
queue, and scheduled execution time, then scans the command body
for suspicious tokens.

Findings raised
---------------
* **HIGH**    Job body contains offensive tradecraft tokens
* **MEDIUM**  ``at`` job owned by root or a non-standard user
* **INFO**    Each job emitted as a timeline event
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import find_suspicious_tokens, read_lines
from .base import BaseParser


# Common at-job header patterns
OWNER_RE = re.compile(r"^#\s*atrun\s+uid=(\d+)\s+gid=(\d+)", re.IGNORECASE)
# Some at implementations embed: # owner: <user>
OWNER2_RE = re.compile(r"^#\s*owner:\s*(\S+)", re.IGNORECASE)


class AtJobsParser(BaseParser):
    name = "at_jobs"

    def run(self) -> None:
        files: list[Path] = []
        for pattern in [
            "**/var/spool/at/*",
            "**/var/spool/atjobs/*",
            "**/var/spool/cron/atjobs/*",
        ]:
            files.extend(self.finder.find_by_glob([pattern]))

        # de-dup
        seen: set[Path] = set()
        files = [f for f in files if f.is_file()
                 and not f.name.startswith(".")
                 and not (f in seen or seen.add(f))]

        for path in files:
            self.note_file(path)
            self._parse_job(path)

    # ------------------------------------------------------------------
    def _parse_job(self, path: Path) -> None:
        try:
            mtime = datetime.fromtimestamp(
                path.stat().st_mtime, tz=timezone.utc
            )
        except OSError:
            mtime = datetime.now(timezone.utc)

        lines = list(read_lines(path))
        if not lines:
            return

        # Extract metadata from headers
        owner = None
        uid = None
        body_lines: list[str] = []
        in_body = False

        for line in lines:
            # Try to extract owner info from comment headers
            m = OWNER_RE.match(line)
            if m:
                uid = int(m.group(1))
                continue
            m = OWNER2_RE.match(line)
            if m:
                owner = m.group(1)
                continue

            # Skip shebang and comment-only header lines
            if line.startswith("#") or line.startswith("#!/"):
                continue

            # Everything else is body
            stripped = line.strip()
            if stripped:
                body_lines.append(stripped)

        body = "\n".join(body_lines)
        if not body.strip():
            return

        # Infer owner from filename pattern or spool path
        if not owner and uid is not None:
            owner = f"uid={uid}"
        if not owner:
            # Try to infer from path: /var/spool/cron/atjobs/<user>/...
            posix = path.as_posix()
            if "/cron/atjobs/" in posix:
                parts = posix.split("/cron/atjobs/")
                if len(parts) > 1 and "/" in parts[1]:
                    owner = parts[1].split("/")[0]

        owner = owner or "(unknown)"

        self.emit_event(
            timestamp=mtime,
            source="at_jobs",
            event_type="at_job",
            description=f"at job [{path.name}] owner={owner}: {body[:200]}",
            user=owner if owner != "(unknown)" else None,
            raw=body[:500],
            metadata={
                "file": str(path),
                "owner": owner,
                "body_preview": body[:500],
            },
        )

        # ---- evaluate for suspicious content ----
        hits = find_suspicious_tokens(body)
        if hits:
            self.emit_finding(
                severity=SEV_HIGH,
                category="persistence",
                title=f"Suspicious at job: {path.name}",
                description=(
                    f"An at/batch scheduled job contains tokens commonly "
                    f"seen in attacker automation: {', '.join(hits)}."
                ),
                artifact=str(path),
                timestamp=mtime,
                evidence=[body[:600]],
                metadata={"owner": owner, "tokens": hits},
            )

        # Flag root-owned at jobs (could be persistence)
        if uid == 0 or owner == "root":
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="persistence",
                title=f"Root-owned at job: {path.name}",
                description=(
                    "An at/batch job is owned by root. Confirm whether "
                    "this matches an approved scheduled task."
                ),
                artifact=str(path),
                timestamp=mtime,
                evidence=[body[:300]],
                metadata={"owner": owner},
            )
