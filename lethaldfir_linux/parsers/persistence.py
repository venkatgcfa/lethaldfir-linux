"""
parsers.persistence
===================

Hunts for persistence-friendly artifacts that don't fit cleanly into the
other parsers. This module is the catch-all for the long tail of Linux
persistence techniques.

Checks performed
----------------
* ``/etc/ld.so.preload`` exists / is non-empty -> CRITICAL
* ``/etc/profile``, ``/etc/profile.d/*``, ``/etc/bash.bashrc``,
  ``/etc/bashrc`` containing suspicious tokens -> HIGH
* Per-user ``.bashrc``, ``.bash_profile``, ``.profile``, ``.zshrc``,
  ``.bash_login``, ``.bash_logout`` containing suspicious tokens -> HIGH
* ``/etc/rc.local`` non-trivial content -> MEDIUM
* SUID / SGID binaries outside the standard allow-list -> MEDIUM
* ``.so`` files in ``/etc/ld.so.conf.d/`` pointing to writable dirs -> MEDIUM
* MOTD scripts under ``/etc/update-motd.d/`` -> MEDIUM if suspicious
* ``/etc/xdg/autostart/*.desktop`` referencing odd paths -> LOW
"""

from __future__ import annotations

import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_CRITICAL, SEV_HIGH, SEV_LOW, SEV_MEDIUM
from ..core.utils import find_suspicious_tokens, read_lines
from .base import BaseParser


# Common legitimate SUID binaries (Debian/Ubuntu/RHEL union).
ALLOWED_SUID = {
    "su", "sudo", "passwd", "chsh", "chfn", "newgrp", "gpasswd",
    "umount", "mount", "ping", "ping6", "fusermount", "fusermount3",
    "pkexec", "ksu", "at", "crontab", "ssh-agent",
    "Xorg.wrap", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
    "vmware-user-suid-wrapper", "pmount", "pumount", "wall",
    "mtr-packet", "traceroute6.iputils", "expiry",
    "unix_chkpwd", "ntfs-3g", "exim4", "sendmail", "postdrop",
    "postqueue", "userhelper", "usernetctl",
}

GLOBAL_PROFILE_FILES = (
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zsh/zshenv",
    "/etc/zsh/zshrc",
    "/etc/csh.cshrc",
    "/etc/csh.login",
    "/etc/environment",
)

PER_USER_RC_FILES = (
    ".bashrc", ".bash_profile", ".profile", ".bash_login",
    ".bash_logout", ".zshrc", ".zshenv", ".zlogin", ".zlogout",
    ".kshrc", ".cshrc",
)


class PersistenceParser(BaseParser):
    name = "persistence"

    def run(self) -> None:
        self._check_ld_preload()
        self._check_global_profiles()
        self._check_user_rc_files()
        self._check_rc_local()
        self._check_suid_sgid()
        self._check_motd_scripts()
        self._check_xdg_autostart()
        self._check_ld_conf_d()

    # ------------------------------------------------------------------
    def _stat_ts(self, path: Path) -> datetime:
        try:
            return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            return datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    def _check_ld_preload(self) -> None:
        for f in self.finder.find_by_suffix(["/etc/ld.so.preload"]):
            self.note_file(f)
            ts = self._stat_ts(f)
            content = "\n".join(line for line in read_lines(f) if line.strip())
            if content:
                self.emit_event(
                    timestamp=ts,
                    source="ld.so.preload",
                    event_type="ld_preload_present",
                    description=f"/etc/ld.so.preload contains: {content}",
                    metadata={"content": content},
                )
                self.emit_finding(
                    severity=SEV_CRITICAL,
                    category="persistence",
                    title="/etc/ld.so.preload is populated",
                    description=(
                        "/etc/ld.so.preload forces the listed shared objects to "
                        "be loaded into every dynamically linked process. It is "
                        "almost always empty on production hosts; a non-empty "
                        "file is a high-confidence indicator of a userland "
                        "rootkit."
                    ),
                    artifact=str(f),
                    timestamp=ts,
                    evidence=[content],
                )

    # ------------------------------------------------------------------
    def _check_global_profiles(self) -> None:
        # named files
        for suffix in GLOBAL_PROFILE_FILES:
            for f in self.finder.find_by_suffix([suffix]):
                self.note_file(f)
                self._scan_rc(f, scope="global")
        # /etc/profile.d/* drop-ins
        for f in self.finder.find_by_glob(["**/etc/profile.d/*"]):
            if f.is_file():
                self.note_file(f)
                self._scan_rc(f, scope="global")

    def _check_user_rc_files(self) -> None:
        for rc in PER_USER_RC_FILES:
            for f in self.finder.find_by_glob([f"**/{rc}"]):
                if not f.is_file():
                    continue
                # restrict to home / root
                posix = f.as_posix()
                if "/home/" not in posix and "/root/" not in posix:
                    continue
                self.note_file(f)
                self._scan_rc(f, scope="user")

    def _scan_rc(self, path: Path, scope: str) -> None:
        ts = self._stat_ts(path)
        content_lines = list(read_lines(path))
        full = "\n".join(content_lines)
        hits = find_suspicious_tokens(full)
        if hits:
            self.emit_finding(
                severity=SEV_HIGH,
                category="persistence",
                title=f"Suspicious tokens in {scope} shell rc file",
                description=(
                    f"Shell startup file '{path.name}' contains tokens "
                    f"associated with attacker tradecraft: {', '.join(hits)}."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[
                    line for line in content_lines
                    if any(t in line.lower() for t in hits)
                ][:10],
                metadata={"scope": scope, "tokens": hits},
            )

    # ------------------------------------------------------------------
    def _check_rc_local(self) -> None:
        for f in self.finder.find_by_suffix(["/etc/rc.local"]):
            self.note_file(f)
            ts = self._stat_ts(f)
            lines = [
                line.strip() for line in read_lines(f)
                if line.strip() and not line.strip().startswith("#")
                and line.strip() not in {"exit 0", "true"}
            ]
            if lines:
                self.emit_event(
                    timestamp=ts,
                    source="rc.local",
                    event_type="rc_local_content",
                    description=f"/etc/rc.local contains {len(lines)} active line(s)",
                    metadata={"lines": lines},
                )
                hits = find_suspicious_tokens("\n".join(lines))
                self.emit_finding(
                    severity=SEV_HIGH if hits else SEV_MEDIUM,
                    category="persistence",
                    title="/etc/rc.local has active commands",
                    description=(
                        "rc.local runs as root at boot. Confirm every command "
                        "below is part of the approved baseline."
                        + (f" Suspicious tokens detected: {', '.join(hits)}." if hits else "")
                    ),
                    artifact=str(f),
                    timestamp=ts,
                    evidence=lines[:20],
                    metadata={"tokens": hits},
                )

    # ------------------------------------------------------------------
    def _check_suid_sgid(self) -> None:
        # Walk the entire evidence root; only check regular files we can stat.
        for f in self.finder.all_files():
            try:
                st = f.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            mode = st.st_mode
            is_suid = bool(mode & stat.S_ISUID)
            is_sgid = bool(mode & stat.S_ISGID)
            if not (is_suid or is_sgid):
                continue
            ts = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
            name = f.name
            self.emit_event(
                timestamp=ts,
                source="filesystem",
                event_type="suid_sgid_binary",
                description=(
                    f"{'SUID' if is_suid else ''}{'+SGID' if is_suid and is_sgid else ('SGID' if is_sgid else '')} "
                    f"binary: {f}"
                ),
                metadata={
                    "path": str(f), "mode": oct(mode),
                    "uid": st.st_uid, "gid": st.st_gid,
                    "size": st.st_size,
                },
            )
            posix = f.as_posix()
            in_user_dir = (
                "/home/" in posix or "/tmp/" in posix
                or "/var/tmp/" in posix or "/dev/shm/" in posix
            )
            unusual_dir = not any(
                f"/{p}/" in posix
                for p in ("bin", "sbin", "usr", "opt", "snap", "libexec")
            )
            if in_user_dir or unusual_dir or name not in ALLOWED_SUID:
                sev = SEV_HIGH if in_user_dir else SEV_MEDIUM
                self.emit_finding(
                    severity=sev,
                    category="privilege_escalation",
                    title=f"Unusual SUID/SGID binary: {name}",
                    description=(
                        f"SUID/SGID bit on a binary not present in the standard "
                        f"allow-list: {f}"
                    ),
                    artifact=str(f),
                    timestamp=ts,
                    metadata={
                        "path": str(f), "mode": oct(mode),
                        "uid": st.st_uid, "gid": st.st_gid,
                    },
                )

    # ------------------------------------------------------------------
    def _check_motd_scripts(self) -> None:
        for f in self.finder.find_by_glob(["**/etc/update-motd.d/*"]):
            if not f.is_file():
                continue
            self.note_file(f)
            ts = self._stat_ts(f)
            full = "\n".join(read_lines(f))
            hits = find_suspicious_tokens(full)
            if hits:
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="persistence",
                    title=f"Suspicious tokens in update-motd.d script: {f.name}",
                    description=(
                        "MOTD scripts execute on every interactive SSH login. "
                        f"This file contains: {', '.join(hits)}."
                    ),
                    artifact=str(f),
                    timestamp=ts,
                    evidence=[full[:500]],
                )

    # ------------------------------------------------------------------
    def _check_xdg_autostart(self) -> None:
        for f in self.finder.find_by_glob([
            "**/etc/xdg/autostart/*.desktop",
            "**/.config/autostart/*.desktop",
        ]):
            if not f.is_file():
                continue
            self.note_file(f)
            ts = self._stat_ts(f)
            for line in read_lines(f):
                if line.startswith("Exec="):
                    cmd = line[5:]
                    hits = find_suspicious_tokens(cmd)
                    if hits or any(p in cmd for p in ("/tmp/", "/var/tmp/", "/dev/shm/")):
                        self.emit_finding(
                            severity=SEV_LOW,
                            category="persistence",
                            title=f"Autostart entry with unusual Exec= : {f.name}",
                            description=(
                                "An XDG autostart .desktop file references an "
                                "unusual Exec target."
                            ),
                            artifact=str(f),
                            timestamp=ts,
                            evidence=[cmd],
                        )
                    break

    # ------------------------------------------------------------------
    def _check_ld_conf_d(self) -> None:
        for f in self.finder.find_by_glob(["**/etc/ld.so.conf.d/*.conf"]):
            if not f.is_file():
                continue
            self.note_file(f)
            ts = self._stat_ts(f)
            for line in read_lines(f):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if any(p in line for p in ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")):
                    self.emit_finding(
                        severity=SEV_MEDIUM,
                        category="persistence",
                        title=f"Suspicious library path in ld.so.conf.d: {f.name}",
                        description=(
                            "ld.so.conf.d entry points to a writable / user "
                            "location. This can be used to plant rogue shared "
                            "libraries."
                        ),
                        artifact=str(f),
                        timestamp=ts,
                        evidence=[line],
                    )
