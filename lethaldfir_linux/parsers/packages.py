"""
parsers.packages
================

Parses package manager logs to produce a chronological inventory of
package installs / upgrades / removals:

* ``/var/log/dpkg.log``         (Debian/Ubuntu raw dpkg)
* ``/var/log/apt/history.log``  (Debian/Ubuntu apt)
* ``/var/log/yum.log``          (RHEL 6/7)
* ``/var/log/dnf.log``          (RHEL 8+/Fedora)

Each install / upgrade / remove is emitted as a timeline event. Removal
of common forensic / monitoring agents (auditd, falco, osquery, etc.) is
flagged as a finding.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH
from ..core.utils import read_lines
from .base import BaseParser


# dpkg.log:  2024-09-01 14:22:11 install pkg:amd64 <noversion> 1.2.3
# Note: dpkg "status" lines (e.g. "status installed pkg:amd64 1.2.3") are
# deliberately excluded — their second token is the dpkg STATE word, not a
# package, so matching them bound pkg="installed"/"unpacked"/... and flooded
# the timeline with bogus events. The install/upgrade/remove/purge action
# lines already carry the real package + version transitions.
DPKG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>install|upgrade|remove|purge)\s+"
    r"(?P<pkg>\S+?)(?::\S+)?\s+"
    r"(?P<old>\S+)\s+(?P<new>\S+)?$"
)

# apt history.log entries are blocks separated by blank lines
APT_START_RE = re.compile(r"^Start-Date:\s+(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")
APT_CMD_RE   = re.compile(r"^Commandline:\s+(?P<cmd>.+)$")
APT_INSTALL_RE = re.compile(r"^(?P<action>Install|Upgrade|Remove|Purge|Reinstall|Downgrade):\s+(?P<pkgs>.+)$")
APT_REQ_RE   = re.compile(r"^Requested-By:\s+(?P<user>\S+)")

# yum.log:  Sep 01 14:22:11 Installed: pkg-1.2.3-1.el7.x86_64
YUM_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>Installed|Updated|Erased):\s+(?P<pkg>\S+)"
)

# dnf.log:  2024-09-01T14:22:11+0530 INFO Installed: pkg-1.2.3
DNF_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})\s+\S+\s+"
    r"(?P<action>Installed|Upgraded|Removed):\s+(?P<pkg>\S+)"
)


SECURITY_PACKAGES = {
    "auditd", "audit", "osquery", "osqueryd", "falco", "wazuh-agent",
    "ossec-hids", "tripwire", "aide", "sysmon", "auditbeat", "filebeat",
    "clamav", "clamd", "rkhunter", "chkrootkit", "selinux-policy",
    "apparmor", "apparmor-utils", "fail2ban", "ufw", "firewalld",
    "snort", "suricata",
}


class PackageLogParser(BaseParser):
    name = "package_logs"

    def run(self) -> None:
        # dpkg.log family
        for f in self.finder.find_log_family("dpkg.log"):
            self.note_file(f)
            self._parse_dpkg(f)

        # apt history.log family
        for f in self.finder.find_log_family("history.log"):
            if "/apt/" in f.as_posix():
                self.note_file(f)
                self._parse_apt(f)

        # yum.log family
        for f in self.finder.find_log_family("yum.log"):
            self.note_file(f)
            self._parse_yum(f)

        # dnf.log family - dnf.log, dnf.rpm.log
        for f in self.finder.find_by_glob([
            "**/var/log/dnf.log*",
            "**/var/log/dnf.rpm.log*",
        ]):
            self.note_file(f)
            self._parse_dnf(f)

    # ------------------------------------------------------------------
    def _parse_dpkg(self, path: Path) -> None:
        for line in read_lines(path):
            m = DPKG_RE.match(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            action = m["action"]
            pkg = m["pkg"]
            self.emit_event(
                timestamp=ts,
                source="dpkg.log",
                event_type=f"package_{action}",
                description=f"dpkg {action}: {pkg} ({m['old']} -> {m['new'] or '-'})",
                metadata={"package": pkg, "action": action, "old": m["old"], "new": m["new"]},
                raw=line,
            )
            self._maybe_finding(action, pkg, str(path), ts)

    def _parse_apt(self, path: Path) -> None:
        block: dict[str, str] = {}
        for raw in read_lines(path):
            line = raw.rstrip()
            if not line:
                if block:
                    self._flush_apt(block, path)
                    block = {}
                continue
            for rx, key in (
                (APT_START_RE, "ts"),
                (APT_CMD_RE,   "cmd"),
                (APT_REQ_RE,   "user"),
            ):
                m = rx.match(line)
                if m:
                    block[key] = m.group(1) if key != "user" else m.group("user")
                    break
            else:
                m = APT_INSTALL_RE.match(line)
                if m:
                    block.setdefault("ops", []).append(  # type: ignore[union-attr]
                        (m.group("action"), m.group("pkgs"))
                    )
        if block:
            self._flush_apt(block, path)

    def _flush_apt(self, block: dict, path: Path) -> None:
        if "ts" not in block:
            return
        try:
            ts = datetime.strptime(block["ts"], "%Y-%m-%d  %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            try:
                ts = datetime.strptime(block["ts"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                return
        cmd = block.get("cmd", "")
        user = block.get("user", "")
        for action, pkgs in block.get("ops", []):
            for pkg_entry in pkgs.split(", "):
                pkg = pkg_entry.split(" ")[0].split(":")[0]
                self.emit_event(
                    timestamp=ts,
                    source="apt/history.log",
                    event_type=f"package_{action.lower()}",
                    description=f"apt {action.lower()}: {pkg} (cmd={cmd or '-'})",
                    user=user or None,
                    raw=f"{block['ts']}  {action}: {pkg_entry}",
                    metadata={
                        "package": pkg, "action": action.lower(),
                        "command": cmd, "user": user,
                    },
                )
                self._maybe_finding(action.lower(), pkg, str(path), ts)

    def _parse_yum(self, path: Path) -> None:
        year = datetime.now(timezone.utc).year
        for line in read_lines(path):
            m = YUM_RE.match(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            action = m["action"].lower()  # Installed/Updated/Erased
            pkg = m["pkg"]
            self.emit_event(
                timestamp=ts,
                source="yum.log",
                event_type=f"package_{action}",
                description=f"yum {action}: {pkg}",
                metadata={"package": pkg, "action": action},
                raw=line,
            )
            self._maybe_finding(action, pkg, str(path), ts)

    def _parse_dnf(self, path: Path) -> None:
        for line in read_lines(path):
            m = DNF_RE.search(line)
            if not m:
                continue
            try:
                ts = datetime.fromisoformat(
                    m["ts"][:-5] + m["ts"][-5:-2] + ":" + m["ts"][-2:]
                )
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            action = m["action"].lower()
            pkg = m["pkg"]
            self.emit_event(
                timestamp=ts.astimezone(timezone.utc),
                source="dnf.log",
                event_type=f"package_{action}",
                description=f"dnf {action}: {pkg}",
                metadata={"package": pkg, "action": action},
                raw=line,
            )
            self._maybe_finding(action, pkg, str(path), ts)

    # ------------------------------------------------------------------
    def _maybe_finding(self, action: str, pkg: str, artifact: str, ts: datetime) -> None:
        action = action.lower()
        pkg_lower = pkg.lower()
        if action in {"remove", "purge", "erased", "removed"} and \
                any(s in pkg_lower for s in SECURITY_PACKAGES):
            self.emit_finding(
                severity=SEV_HIGH,
                category="defense_evasion",
                title=f"Security package removed: {pkg}",
                description=(
                    f"A security / monitoring package ({pkg}) was uninstalled. "
                    "Confirm whether this matches an authorised change."
                ),
                artifact=artifact,
                timestamp=ts,
                metadata={"package": pkg, "action": action},
            )
