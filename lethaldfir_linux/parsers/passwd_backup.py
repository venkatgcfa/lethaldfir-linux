"""
parsers.passwd_backup
=====================

Locates backup variants of ``/etc/passwd``, ``/etc/shadow``, ``/etc/group``,
``/etc/gshadow`` and diffs them against the live files. Backup files are
created automatically by the ``shadow`` package (``vipw``, ``passwd``,
``useradd`` etc.) and by editors saving swap copies.

Recognised backup names (matched per directory)
-----------------------------------------------
* ``passwd-`` / ``shadow-`` / ``group-`` / ``gshadow-``  — POSIX backup
  format written by shadow utilities.
* ``passwd~`` / ``shadow~``                              — vi / vim backup.
* ``passwd.backup`` / ``shadow.backup``                  — manual sysadmin copy.
* ``passwd.bak``    / ``shadow.bak``                     — manual sysadmin copy.
* ``passwd.old``    / ``shadow.old``                     — manual sysadmin copy.
* ``passwd.save``   / ``shadow.save``                    — manual sysadmin copy.
* ``passwd.orig``   / ``shadow.orig``                    — manual sysadmin copy.
* ``passwd.YYYYMMDD`` patterns                           — date-suffixed copies.

Findings raised
---------------
* **HIGH**     User present in **live** but absent from **backup** -
               account was added (compare timestamps to scope window).
* **HIGH**     User present in **backup** but absent from **live** -
               account was deleted (cleanup of attacker-created accounts
               or legitimate offboarding; flag for review).
* **HIGH**     User's UID changed between backup and live.
* **HIGH**     User's shell changed between backup and live (e.g. from
               ``/usr/sbin/nologin`` to ``/bin/bash`` indicates
               privilege manipulation).
* **HIGH**     User's password hash changed between backup and live
               (legitimate password reset OR account takeover).
* **MEDIUM**   User's GID, GECOS, or home directory changed.
* **MEDIUM**   Backup file present with world-readable permissions
               (shadow-equivalent leak).
* **INFO**     Inventory event for every backup file located.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core.event import SEV_HIGH, SEV_INFO, SEV_MEDIUM
from ..core.utils import read_lines
from .base import BaseParser


# Filenames that are accepted as backup variants of the four account
# files. Tried in order; first directory match wins per logical kind.
_BACKUP_PATTERNS = [
    # POSIX shadow-utils convention
    r"^(passwd|shadow|group|gshadow)-$",
    # Editor backup
    r"^(passwd|shadow|group|gshadow)~$",
    # Generic admin backups
    r"^(passwd|shadow|group|gshadow)\.(backup|bak|old|save|orig)$",
    # Date-suffixed
    r"^(passwd|shadow|group|gshadow)\.\d{6,8}$",
    r"^(passwd|shadow|group|gshadow)-\d{6,8}$",
]
_BACKUP_RE = re.compile("|".join(_BACKUP_PATTERNS), re.IGNORECASE)


class PasswdBackupParser(BaseParser):
    name = "passwd_backup"

    def run(self) -> None:
        # ---- locate every backup-shaped file under /etc ----
        # The finder is suffix-based; we scan all_files for /etc paths
        # whose basename matches one of our backup patterns.
        backups: dict[str, list[Path]] = {
            "passwd": [], "shadow": [], "group": [], "gshadow": [],
        }
        for p in self.finder.all_files():
            posix = p.as_posix()
            if "/etc/" not in posix:
                continue
            m = _BACKUP_RE.match(p.name)
            if not m:
                continue
            kind = next(g for g in m.groups() if g)
            backups[kind].append(p)

        if not any(backups.values()):
            return  # nothing to do

        # ---- inventory events ----
        for kind, paths in backups.items():
            for path in paths:
                self.note_file(path)
                try:
                    mtime = datetime.fromtimestamp(path.stat().st_mtime,
                                                   tz=timezone.utc)
                    size = path.stat().st_size
                    mode = path.stat().st_mode
                except OSError:
                    mtime = datetime.now(timezone.utc); size = 0; mode = 0

                self.emit_event(
                    timestamp=mtime,
                    source="passwd_backup",
                    event_type=f"{kind}_backup_present",
                    description=(
                        f"Backup of /etc/{kind} located: {path.name} "
                        f"({size} bytes)"
                    ),
                    metadata={"kind": kind, "size": size, "path": str(path)},
                    raw=str(path),
                )

                # ---- world-readable shadow-class files ----
                if kind in ("shadow", "gshadow") and (mode & 0o004):
                    self.emit_finding(
                        severity=SEV_MEDIUM,
                        category="credential_exposure",
                        title=f"World-readable {kind} backup: {path.name}",
                        description=(
                            f"Backup of /etc/{kind} at '{path}' has "
                            "world-readable permissions, exposing every "
                            "local password hash to non-privileged users."
                        ),
                        artifact=str(path),
                        timestamp=mtime,
                        metadata={"path": str(path), "mode": oct(mode)},
                    )

        # ---- diff backup vs live for passwd & shadow ----
        # The "live" baseline must be the real /etc/passwd|shadow, not a
        # backup sibling — find_by_suffix also returns passwd-/passwd.bak, and
        # if one of those became the baseline the whole diff was bogus.
        live_users   = self._parse_account_file(
            self._first([p for p in self.finder.find_by_suffix(["/etc/passwd"])
                         if p.name == "passwd"]), "passwd")
        live_shadow  = self._parse_account_file(
            self._first([p for p in self.finder.find_by_suffix(["/etc/shadow"])
                         if p.name == "shadow"]), "shadow")

        for backup_path in backups["passwd"]:
            backup_users = self._parse_account_file(backup_path, "passwd")
            self._diff_passwd(backup_path, backup_users, live_users)

        for backup_path in backups["shadow"]:
            backup_shadow = self._parse_account_file(backup_path, "shadow")
            self._diff_shadow(backup_path, backup_shadow, live_shadow)

    # ------------------------------------------------------------------
    @staticmethod
    def _first(items):
        return items[0] if items else None

    def _parse_account_file(self, path: Path | None, kind: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        if path is None:
            return out
        for line in read_lines(path):
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if kind == "passwd":
                if len(parts) < 7:
                    continue
                name, _x, uid, gid, gecos, home, shell = parts[:7]
                try:
                    uid_i = int(uid); gid_i = int(gid)
                except ValueError:
                    continue
                out[name] = {
                    "name": name, "uid": uid_i, "gid": gid_i,
                    "gecos": gecos, "home": home, "shell": shell,
                }
            elif kind == "shadow":
                if len(parts) < 2:
                    continue
                name, hashv = parts[0], parts[1]
                out[name] = {"name": name, "hash": hashv}
        return out

    # ------------------------------------------------------------------
    def _diff_passwd(self, backup_path: Path, backup: dict, live: dict) -> None:
        try:
            mtime = datetime.fromtimestamp(backup_path.stat().st_mtime,
                                           tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        # --- accounts added since backup (in live but not backup) ---
        added = sorted(set(live) - set(backup))
        for name in added:
            u = live[name]
            self.emit_finding(
                severity=SEV_HIGH,
                category="account_change",
                title=f"User '{name}' added since /etc/passwd backup",
                description=(
                    f"Account '{name}' (uid={u['uid']}, shell={u['shell']}) "
                    f"is present in live /etc/passwd but absent from the "
                    f"backup at '{backup_path.name}'. The account was "
                    "created after the backup was taken — verify the "
                    "creation event in auth.log / dpkg.log / audit.log."
                ),
                artifact=str(backup_path),
                timestamp=mtime,
                evidence=[
                    f"live:    {name}:x:{u['uid']}:{u['gid']}:{u['gecos']}:{u['home']}:{u['shell']}",
                    f"backup:  (absent)",
                ],
                metadata={"user": name, "uid": u["uid"], "shell": u["shell"]},
            )

        # --- accounts removed since backup (in backup but not live) ---
        removed = sorted(set(backup) - set(live))
        for name in removed:
            u = backup[name]
            self.emit_finding(
                severity=SEV_HIGH,
                category="account_change",
                title=f"User '{name}' removed since /etc/passwd backup",
                description=(
                    f"Account '{name}' (uid={u['uid']}, shell={u['shell']}) "
                    f"was present in '{backup_path.name}' but is absent "
                    f"from live /etc/passwd. May indicate cleanup of "
                    "attacker-created accounts OR legitimate offboarding."
                ),
                artifact=str(backup_path),
                timestamp=mtime,
                evidence=[
                    f"backup:  {name}:x:{u['uid']}:{u['gid']}:{u['gecos']}:{u['home']}:{u['shell']}",
                    f"live:    (absent)",
                ],
                metadata={"user": name, "uid": u["uid"], "shell": u["shell"]},
            )

        # --- accounts present in both: per-field comparison ---
        for name in sorted(set(backup) & set(live)):
            b = backup[name]; l = live[name]
            if b["uid"] != l["uid"]:
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="privilege_escalation",
                    title=f"UID changed for '{name}': {b['uid']} -> {l['uid']}",
                    description=(
                        f"Account '{name}' had its UID changed between the "
                        f"backup and live /etc/passwd. UID changes - "
                        "especially to 0 - are strong privilege-escalation "
                        "indicators."
                    ),
                    artifact=str(backup_path),
                    timestamp=mtime,
                    evidence=[
                        f"backup uid: {b['uid']}",
                        f"live   uid: {l['uid']}",
                    ],
                    metadata={"user": name, "old_uid": b["uid"], "new_uid": l["uid"]},
                )
            if b["shell"] != l["shell"]:
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="privilege_escalation",
                    title=f"Shell changed for '{name}': {b['shell']} -> {l['shell']}",
                    description=(
                        f"Account '{name}' had its login shell modified. "
                        "Changing nologin/false to a real shell on a "
                        "service account is a classic persistence move."
                    ),
                    artifact=str(backup_path),
                    timestamp=mtime,
                    evidence=[
                        f"backup shell: {b['shell']}",
                        f"live   shell: {l['shell']}",
                    ],
                    metadata={"user": name, "old_shell": b["shell"], "new_shell": l["shell"]},
                )
            for f, sev in (("gid", SEV_MEDIUM), ("home", SEV_MEDIUM),
                           ("gecos", SEV_MEDIUM)):
                if b[f] != l[f]:
                    self.emit_finding(
                        severity=sev,
                        category="account_change",
                        title=f"{f.upper()} changed for '{name}'",
                        description=(
                            f"Account '{name}' had its {f} changed: "
                            f"'{b[f]}' -> '{l[f]}'."
                        ),
                        artifact=str(backup_path),
                        timestamp=mtime,
                        evidence=[f"backup {f}: {b[f]}", f"live   {f}: {l[f]}"],
                        metadata={"user": name, f"old_{f}": b[f], f"new_{f}": l[f]},
                    )

    # ------------------------------------------------------------------
    def _diff_shadow(self, backup_path: Path, backup: dict, live: dict) -> None:
        try:
            mtime = datetime.fromtimestamp(backup_path.stat().st_mtime,
                                           tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        for name in sorted(set(backup) & set(live)):
            b_hash = backup[name].get("hash", "")
            l_hash = live[name].get("hash", "")
            if b_hash != l_hash:
                # Avoid logging the actual hash text; report change only.
                def _summary(h):
                    if not h:
                        return "(empty)"
                    if h in ("!", "*"):
                        return f"(locked: {h})"
                    if h.startswith("$"):
                        algo_id = h.split("$", 2)[1] if h.count("$") >= 2 else "?"
                        return f"(set: $...$..., algo id={algo_id})"
                    return "(set: legacy DES or non-standard)"

                self.emit_finding(
                    severity=SEV_HIGH,
                    category="credential_change",
                    title=f"Password hash changed for '{name}'",
                    description=(
                        f"Account '{name}' has a different shadow password "
                        f"hash in '{backup_path.name}' vs live /etc/shadow. "
                        "Could be a legitimate password reset or an "
                        "attacker takeover - correlate with auth.log "
                        "passwd events."
                    ),
                    artifact=str(backup_path),
                    timestamp=mtime,
                    evidence=[
                        f"backup hash: {_summary(b_hash)}",
                        f"live   hash: {_summary(l_hash)}",
                    ],
                    metadata={"user": name},
                )
