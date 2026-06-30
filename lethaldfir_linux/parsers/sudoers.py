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
    r"^(?P<who>\S+)\s+(?P<host>\S+)\s*=\s*(?:\((?P<runas>[^)]+)\))?\s*(?P<tags>(?:[A-Z_]+:\s*)*)(?P<cmds>.+)$"
)

# GTFOBins-style binaries that yield a root shell / file write when runnable
# via sudo. A passwordless (NOPASSWD) grant to ANY of these is effectively
# full root, even though the command is not literally "ALL".
GTFOBINS_SUDO = {
    "vi", "vim", "vimdiff", "rvim", "view", "ex", "nano", "pico", "ed",
    "emacs", "less", "more", "man", "most", "awk", "gawk", "sed", "tee",
    "dd", "find", "tar", "zip", "gzip", "bzip2", "xz", "cp", "mv", "env",
    "ftp", "gdb", "nmap", "perl", "python", "python2", "python3", "ruby",
    "php", "lua", "node", "bash", "sh", "dash", "ksh", "zsh", "fish",
    "csh", "tcsh", "su", "script", "socat", "expect", "tclsh", "wish",
    "make", "cmake", "docker", "systemctl", "apt", "apt-get", "dpkg",
    "rpm", "yum", "dnf", "pip", "pip3", "gem", "crontab", "at", "mount",
    "nsenter", "capsh", "chroot", "strace", "ltrace", "taskset", "time",
    "timeout", "watch", "xargs", "flock", "unshare", "busybox", "openssl",
    "rsync", "scp", "ssh", "wget", "curl", "git", "journalctl", "jq",
    "passwd", "tcpdump",
}


def _command_binaries(cmds: str) -> set:
    """Basenames of the binaries named in a sudoers command spec."""
    out: set = set()
    for tok in cmds.replace(",", " ").split():
        if "/" in tok:
            out.add(tok.rsplit("/", 1)[-1])
        elif tok and tok.upper() != "ALL" and not tok.startswith("-"):
            out.add(tok)
    return out


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
        # Note: `!targetpw` is the SAFE default and is NOT flagged (flagging
        # it produced false positives). Real weakeners: !authenticate (no
        # password at all), timestamp_timeout=-1 (credentials cached
        # forever), pwfeedback (Baron Samedit CVE-2019-18634 surface),
        # visiblepw (password echoed over insecure ttys).
        weakeners = [w for w in ("!authenticate", "pwfeedback", "visiblepw",
                                 "timestamp_timeout=-1")
                     if w in low.replace(" ", "")]
        if weakeners:
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="hardening",
                title="Sudo authentication weakened",
                description=(
                    "A Defaults entry weakens sudo authentication: "
                    f"{', '.join(weakeners)}."
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

        # NOPASSWD on a SPECIFIC command (not ALL): the most common real
        # sudo backdoor is passwordless access to a single GTFOBins binary
        # that spawns a root shell (vim, find, less, awk, env, python, ...).
        if is_nopasswd and not is_all_all:
            gtfo = sorted(_command_binaries(cmds) & GTFOBINS_SUDO)
            self.emit_finding(
                severity=SEV_HIGH if gtfo else SEV_MEDIUM,
                category="privilege_escalation",
                title=(
                    f"Passwordless sudo to shell-capable binary "
                    f"({', '.join(gtfo)}) for {rule['who']}"
                    if gtfo else
                    f"Passwordless sudo command for {rule['who']}"
                ),
                description=(
                    f"{rule['who']} can run '{cmds.strip()}' as "
                    f"{rule['runas'] or 'root'} without a password."
                    + (" This binary can spawn a root shell or write "
                       "arbitrary files (GTFOBins)." if gtfo else "")
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[f"{rule['who']} {rule['host']}=({rule['runas']}) {tags} {cmds}"],
                metadata=rule,
            )

        # detect rules letting a user edit sudoers or credential files
        low = cmds.lower()
        if any(t in low for t in ("/etc/sudoers", "visudo", "/etc/sudoers.d",
                                  "/etc/passwd", "/etc/shadow")):
            self.emit_finding(
                severity=SEV_HIGH,
                category="persistence",
                title=f"Sudoers grants {rule['who']} write access to credential/sudoers files",
                description=(
                    f"{rule['who']} can modify sudoers or the passwd/shadow "
                    "databases via sudo - a complete privilege-escalation "
                    "primitive."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[f"{rule['who']} {rule['host']}=({rule['runas']}) {tags} {cmds}"],
                metadata=rule,
            )
