"""
parsers.sudoers
===============

Parses ``/etc/sudoers`` and every drop-in under ``/etc/sudoers.d/``.

Findings raised
---------------
* **CRITICAL** ``ALL ALL=(ALL) NOPASSWD: ALL`` style world-grant
* **HIGH**     User / group with ``NOPASSWD: ALL``
* **HIGH**     User can edit sudoers (``visudo``, ``/etc/sudoers``) - persistence
* **MEDIUM**   ``Defaults !authenticate``  /  ``targetpw`` disabled
* **INFO**     Per-rule inventory event
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM
from ..core.utils import read_lines
from .base import BaseParser


SUDO_RULE_RE = re.compile(
    r"^(?P<who>\S+)\s+(?P<host>\S+)=\s*(?:\((?P<runas>[^)]+)\))?\s*(?P<tags>(?:[A-Z_]+:\s*)*)(?P<cmds>.+)$"
)


class SudoersParser(BaseParser):
    name = "sudoers"

    def run(self) -> None:
        files: list[Path] = []
        files.extend(self.finder.find_by_suffix(["/etc/sudoers"]))
        files.extend(self.finder.find_by_glob(["**/etc/sudoers.d/*"]))
        seen: set[Path] = set()
        files = [f for f in files if f.is_file() and not (f in seen or seen.add(f))]

        for f in files:
            self.note_file(f)
            self._parse_one(f)

    def _parse_one(self, path: Path) -> None:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        for raw in read_lines(path):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("Defaults"):
                self._evaluate_defaults(line, path, mtime)
                continue
            m = SUDO_RULE_RE.match(line)
            if not m:
                continue
            rule = {
                "who": m["who"],
                "host": m["host"],
                "runas": (m["runas"] or "").strip(),
                "tags": (m["tags"] or "").strip(),
                "commands": (m["cmds"] or "").strip(),
                "file": str(path),
            }
            self.emit_event(
                timestamp=mtime,
                source="sudoers",
                event_type="sudo_rule",
                description=(
                    f"sudo rule: {rule['who']} {rule['host']}="
                    f"({rule['runas'] or 'ALL'}) {rule['tags']}{rule['commands']}"
                ),
                metadata=rule,
                raw=line,
            )
            self._evaluate_rule(rule, path, mtime)

    # ------------------------------------------------------------------
    def _evaluate_defaults(self, line: str, path: Path, ts: datetime) -> None:
        low = line.lower()
        if "!authenticate" in low or "!targetpw" in low:
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="hardening",
                title="Sudo authentication weakened",
                description=(
                    "A Defaults entry weakens sudo authentication "
                    "(e.g. !authenticate, !targetpw)."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[line],
            )

    def _evaluate_rule(self, rule: dict, path: Path, ts: datetime) -> None:
        cmds = rule["commands"]
        tags = rule["tags"].upper()
        is_nopasswd = "NOPASSWD:" in tags
        is_all_all = (
            cmds.strip().upper() == "ALL"
            and (rule["runas"].upper() in {"ALL", "ALL : ALL", "ROOT", ""} or
                 rule["runas"].upper().startswith("ALL"))
        )

        if rule["who"].upper() == "ALL" and is_all_all and is_nopasswd:
            self.emit_finding(
                severity=SEV_CRITICAL,
                category="privilege_escalation",
                title="World-readable sudo grant: ALL ALL=(ALL) NOPASSWD: ALL",
                description="Every user can run any command as any user without a password.",
                artifact=str(path),
                timestamp=ts,
                evidence=[f"{rule['who']} {rule['host']}=({rule['runas']}) {tags} {cmds}"],
            )
            return

        if is_nopasswd and is_all_all:
            self.emit_finding(
                severity=SEV_HIGH,
                category="privilege_escalation",
                title=f"NOPASSWD: ALL granted to {rule['who']}",
                description=(
                    f"{rule['who']} can run any command as "
                    f"{rule['runas'] or 'root'} without a password."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[f"{rule['who']} {rule['host']}=({rule['runas']}) {tags} {cmds}"],
                metadata=rule,
            )

        # detect rules letting a user edit sudoers (persistence)
        low = cmds.lower()
        if "/etc/sudoers" in low or "visudo" in low or "/etc/sudoers.d" in low:
            self.emit_finding(
                severity=SEV_HIGH,
                category="persistence",
                title=f"Sudoers grants {rule['who']} permission to modify sudoers",
                description=(
                    f"{rule['who']} can modify the sudoers file itself - this "
                    "is a complete privilege-escalation primitive."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[f"{rule['who']} {rule['host']}=({rule['runas']}) {tags} {cmds}"],
                metadata=rule,
            )
