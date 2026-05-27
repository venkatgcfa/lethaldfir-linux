"""
parsers.cron
============

Enumerates every cron entry on the system:

* ``/etc/crontab``
* ``/etc/cron.d/*``
* ``/etc/cron.{hourly,daily,weekly,monthly}/*``
* ``/var/spool/cron/crontabs/*`` (Debian)
* ``/var/spool/cron/*``          (RHEL)
* ``/etc/anacrontab``

For every entry it emits a ``cron_entry`` timeline event (using the file
mtime as the timestamp anchor) and raises findings for entries that
look suspicious (downloads-and-executes, encoded commands, paths in
``/tmp``, ``/dev/shm``, etc.).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_INFO, SEV_MEDIUM
from ..core.utils import find_suspicious_tokens, read_lines
from .base import BaseParser


# system crontab line:    m h dom mon dow user command
SYSTEM_CRON_RE = re.compile(
    r"^(?P<m>\S+)\s+(?P<h>\S+)\s+(?P<dom>\S+)\s+(?P<mon>\S+)\s+(?P<dow>\S+)\s+(?P<user>\S+)\s+(?P<cmd>.+)$"
)
# user crontab line (no user field): m h dom mon dow command
USER_CRON_RE = re.compile(
    r"^(?P<m>\S+)\s+(?P<h>\S+)\s+(?P<dom>\S+)\s+(?P<mon>\S+)\s+(?P<dow>\S+)\s+(?P<cmd>.+)$"
)
SHORTCUT_RE = re.compile(
    r"^(?P<sched>@(?:reboot|yearly|annually|monthly|weekly|daily|midnight|hourly))\s+(?:(?P<user>\S+)\s+)?(?P<cmd>.+)$"
)


CRON_FRAGMENT_DIRS = (
    "/etc/cron.d/",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
)


class CronParser(BaseParser):
    name = "cron"

    def run(self) -> None:
        entries: list[dict] = []

        # ---- /etc/crontab and /etc/anacrontab ----
        for suffix in ("/etc/crontab", "/etc/anacrontab"):
            for f in self.finder.find_by_suffix([suffix]):
                self.note_file(f)
                entries.extend(self._parse_file(f, has_user_field=True))

        # ---- /etc/cron.d/* and other fragment dirs (system-style) ----
        for d in CRON_FRAGMENT_DIRS:
            for f in self.finder.find_by_suffix([d]):
                if f.is_file():
                    self.note_file(f)
                    is_dropfile_dir = d.endswith(".d/")
                    entries.extend(
                        self._parse_file(f, has_user_field=is_dropfile_dir)
                    )

        # ---- per-user crontabs ----
        # /var/spool/cron/<user> or /var/spool/cron/crontabs/<user>
        for f in self.finder.find_by_glob([
            "**/var/spool/cron/*",
            "**/var/spool/cron/crontabs/*",
        ]):
            if f.is_file():
                self.note_file(f)
                user = f.name
                entries.extend(self._parse_file(f, has_user_field=False, fixed_user=user))

        self.case.set_artifact("cron_entries", entries)

    # ------------------------------------------------------------------
    def _parse_file(
        self,
        path: Path,
        has_user_field: bool,
        fixed_user: str | None = None,
    ) -> list[dict]:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        out: list[dict] = []
        for raw in read_lines(path):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # ignore env assignments: PATH=..., MAILTO=..., SHELL=...
            if re.match(r"^[A-Z_][A-Z0-9_]*\s*=", line):
                continue

            entry = self._parse_line(line, has_user_field, fixed_user)
            if not entry:
                continue
            entry["file"] = str(path)

            self.emit_event(
                timestamp=mtime,
                source="cron",
                event_type="cron_entry",
                description=(
                    f"cron[{entry.get('user') or '?'}] "
                    f"sched={entry['schedule']} cmd={entry['command']}"
                ),
                user=entry.get("user"),
                raw=line,
                metadata=entry,
            )

            self._evaluate_entry(entry, path, mtime)
            out.append(entry)

        return out

    @staticmethod
    def _parse_line(line: str, has_user_field: bool, fixed_user: str | None):
        m = SHORTCUT_RE.match(line)
        if m:
            user = m.group("user") if has_user_field else fixed_user
            return {
                "schedule": m["sched"],
                "user": user,
                "command": m["cmd"].strip(),
            }

        if has_user_field:
            m = SYSTEM_CRON_RE.match(line)
            if m:
                return {
                    "schedule": f"{m['m']} {m['h']} {m['dom']} {m['mon']} {m['dow']}",
                    "user": m["user"],
                    "command": m["cmd"].strip(),
                }
        else:
            m = USER_CRON_RE.match(line)
            if m:
                return {
                    "schedule": f"{m['m']} {m['h']} {m['dom']} {m['mon']} {m['dow']}",
                    "user": fixed_user,
                    "command": m["cmd"].strip(),
                }
        return None

    def _evaluate_entry(self, entry: dict, path: Path, ts: datetime) -> None:
        cmd = entry["command"]
        hits = find_suspicious_tokens(cmd)
        if hits:
            self.emit_finding(
                severity=SEV_HIGH,
                category="persistence",
                title=f"Suspicious cron command for user '{entry.get('user')}'",
                description=(
                    "A scheduled cron command contains tokens commonly seen "
                    f"in malicious automation: {', '.join(hits)}."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[cmd],
                metadata=entry,
            )
        elif entry["schedule"] == "@reboot":
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="persistence",
                title=f"@reboot cron entry for '{entry.get('user')}'",
                description=(
                    "A cron entry runs at every system boot. Confirm the "
                    "command is part of an approved baseline."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[cmd],
                metadata=entry,
            )
