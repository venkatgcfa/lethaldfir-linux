"""
parsers.history_files
=====================

Parses interactive shell and REPL history for every user under
``/home/*`` and ``/root/``.

Files covered
-------------
* ``.bash_history`` (with optional ``HISTTIMEFORMAT`` epoch markers)
* ``.zsh_history``  (zsh extended-history format ``: <epoch>:<dur>;<cmd>``)
* ``.ash_history``, ``.sh_history``
* ``.python_history``, ``.mysql_history``, ``.psql_history``,
  ``.sqlite_history``, ``.lesshst``, ``.viminfo`` (best-effort)

Findings raised
---------------
* **HIGH**   Any command containing tokens such as ``curl ... | sh``,
             ``nc -e``, ``/dev/tcp/``, ``base64 -d``, ``chmod +s``, etc.
* **MEDIUM** ``history -c`` / ``unset HISTFILE`` (anti-forensic)
* **LOW**    Editing of sensitive files (``/etc/passwd``, ``/etc/shadow``,
             ``/etc/sudoers``, ``authorized_keys``)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_LOW, SEV_MEDIUM
from ..core.utils import find_suspicious_tokens, read_lines
from .base import BaseParser


ZSH_RE = re.compile(r"^:\s*(?P<epoch>\d+):(?P<dur>\d+);(?P<cmd>.*)$")
BASH_TS_RE = re.compile(r"^#(?P<epoch>\d{9,11})$")

ANTIFORENSIC_PATTERNS = (
    "history -c", "unset histfile", "export histfile=/dev/null",
    "rm ~/.bash_history", "rm /root/.bash_history",
    "ln -sf /dev/null ~/.bash_history",
    "cat /dev/null > ~/.bash_history",
    "shred ~/.bash_history",
)

SENSITIVE_EDITS = re.compile(
    r"(?:vi(?:m)?|nano|emacs|sed|awk)\s+.*?(/etc/passwd|/etc/shadow|/etc/sudoers|"
    r"authorized_keys|/etc/ssh/sshd_config|/etc/crontab|/etc/hosts)\b"
)


class HistoryFilesParser(BaseParser):
    name = "history_files"

    HISTORY_FILES = (
        ".bash_history", ".zsh_history", ".ash_history", ".sh_history",
        ".python_history", ".mysql_history", ".psql_history",
        ".sqlite_history", ".lesshst",
    )

    def run(self) -> None:
        files: list[Path] = []
        for hf in self.HISTORY_FILES:
            files.extend(self.finder.find_by_glob([f"**/{hf}"]))
        # de-dup
        seen: set[Path] = set()
        files = [f for f in files if not (f in seen or seen.add(f))]

        for path in files:
            self.note_file(path)
            user = self._infer_user(path)
            self._parse_one(path, user)

    # ------------------------------------------------------------------
    @staticmethod
    def _infer_user(path: Path) -> str:
        parts = path.as_posix().split("/")
        for i, p in enumerate(parts):
            if p == "home" and i + 1 < len(parts):
                return parts[i + 1]
            if p == "root":
                return "root"
        return "(unknown)"

    def _parse_one(self, path: Path, user: str) -> None:
        name = path.name.lower()
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        if name == ".zsh_history":
            self._parse_zsh(path, user, mtime)
        else:
            self._parse_bash_like(path, user, mtime, name)

    def _parse_bash_like(
        self, path: Path, user: str, mtime: datetime, source_label: str
    ) -> None:
        pending_ts: datetime | None = None
        for raw in read_lines(path):
            line = raw.rstrip("\r")
            if not line:
                continue
            m = BASH_TS_RE.match(line)
            if m:
                try:
                    pending_ts = datetime.fromtimestamp(int(m["epoch"]), tz=timezone.utc)
                except (ValueError, OSError):
                    pending_ts = None
                continue
            ts = pending_ts or mtime
            self._emit_command(line, user, ts, path, source_label)
            pending_ts = None

    def _parse_zsh(self, path: Path, user: str, mtime: datetime) -> None:
        for raw in read_lines(path):
            line = raw.rstrip("\r")
            if not line:
                continue
            m = ZSH_RE.match(line)
            if m:
                try:
                    ts = datetime.fromtimestamp(int(m["epoch"]), tz=timezone.utc)
                except (ValueError, OSError):
                    ts = mtime
                cmd = m["cmd"]
            else:
                ts = mtime
                cmd = line
            self._emit_command(cmd, user, ts, path, ".zsh_history")

    # ------------------------------------------------------------------
    def _emit_command(
        self,
        command: str,
        user: str,
        ts: datetime,
        path: Path,
        source_label: str,
    ) -> None:
        if not command.strip():
            return

        self.emit_event(
            timestamp=ts,
            source=source_label,
            event_type="shell_command",
            description=f"{user}: {command}",
            user=user,
            raw=command,
            metadata={"history_file": str(path)},
        )

        # ---- anti-forensic ----
        low = command.lower()
        for pat in ANTIFORENSIC_PATTERNS:
            if pat in low:
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="defense_evasion",
                    title="Anti-forensic shell command",
                    description=(
                        f"User '{user}' executed an anti-forensic command "
                        f"intended to clear or disable shell history."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[command],
                    metadata={"user": user},
                )
                break

        # ---- offensive tokens ----
        hits = find_suspicious_tokens(command)
        if hits:
            self.emit_finding(
                severity=SEV_HIGH,
                category="suspicious_command",
                title=f"Suspicious command in {user} history",
                description=(
                    f"Command executed by '{user}' contains tokens "
                    f"associated with attacker tradecraft: {', '.join(hits)}"
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[command],
                metadata={"user": user, "tokens": hits},
            )

        # ---- sensitive edits ----
        m = SENSITIVE_EDITS.search(command)
        if m:
            self.emit_finding(
                severity=SEV_LOW,
                category="sensitive_file_access",
                title=f"Edit of sensitive file: {m.group(1)}",
                description=(
                    f"User '{user}' opened a sensitive system file in an "
                    f"editor."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[command],
                metadata={"user": user, "target": m.group(1)},
            )
