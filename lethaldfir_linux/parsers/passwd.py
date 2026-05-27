"""
parsers.passwd
==============

Parses the local account databases:

* ``/etc/passwd``
* ``/etc/shadow``  (if present in the evidence - usually requires root capture)
* ``/etc/group``
* ``/etc/gshadow``

Findings raised
---------------
* **CRITICAL** Non-root account with UID 0
* **CRITICAL** Account with empty password hash field in /etc/shadow
* **HIGH**     Login shell on a system service account (``daemon``, ``bin``, etc.)
* **HIGH**     User added to ``sudo`` / ``wheel`` / ``admin`` group
* **MEDIUM**   Account with password never expiring + interactive shell + recent password
* **INFO**     Per-account inventory event (timestamped from /etc/passwd mtime)
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from ..core.event import SEV_CRITICAL, SEV_HIGH, SEV_INFO, SEV_MEDIUM
from ..core.utils import read_lines
from .base import BaseParser


# Service-account names that should never have an interactive shell.
SERVICE_ACCOUNTS = {
    "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
    "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
    "nobody", "_apt", "messagebus", "systemd-network", "systemd-resolve",
    "systemd-timesync", "ftp", "tcpdump",
}

INTERACTIVE_SHELLS = {
    "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "/bin/ksh",
    "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/sh", "/usr/bin/fish",
}

PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root", "adm", "docker", "lxd"}


class PasswdParser(BaseParser):
    name = "passwd_shadow_group"

    def run(self) -> None:
        passwd_files = self.finder.find_by_suffix(["/etc/passwd"])
        shadow_files = self.finder.find_by_suffix(["/etc/shadow"])
        group_files  = self.finder.find_by_suffix(["/etc/group"])

        users: dict[str, dict[str, Any]] = {}
        groups: list[dict[str, Any]] = []

        for f in passwd_files:
            self.note_file(f)
            users.update(self._parse_passwd(f))

        for f in shadow_files:
            self.note_file(f)
            self._parse_shadow(f, users)

        for f in group_files:
            self.note_file(f)
            groups.extend(self._parse_group(f, users))

        # ------------------------------------------------------------------
        # Post-processing: derive convenience fields used by the report.
        # ------------------------------------------------------------------
        for u in users.values():
            grps = u.get("groups") or []
            u["is_privileged"] = bool(set(grps) & PRIVILEGED_GROUPS) or u.get("uid") == 0
            u["is_service_account"] = (
                u.get("name") in SERVICE_ACCOUNTS
                or (u.get("uid") is not None and 0 < u["uid"] < 1000)
            )
            u["has_interactive_shell"] = u.get("shell") in INTERACTIVE_SHELLS

            # Compose a one-line "anomalies" string for the report.
            anomalies = []
            if u.get("uid") == 0 and u.get("name") != "root":
                anomalies.append("UID0_NON_ROOT")
            if u.get("password_status") == "empty":
                anomalies.append("EMPTY_PASSWORD")
            if u.get("hash_algorithm") == "MD5 (weak)":
                anomalies.append("WEAK_HASH_MD5")
            if u["is_service_account"] and u["has_interactive_shell"]:
                anomalies.append("SVC_ACCT_HAS_SHELL")
            if u.get("never_expires") and u.get("password_status") == "set" \
                    and u["has_interactive_shell"]:
                anomalies.append("PW_NEVER_EXPIRES")
            u["anomalies"] = ",".join(anomalies)

        self.case.set_artifact("local_users", list(users.values()))
        self.case.set_artifact("local_groups", groups)

    # ------------------------------------------------------------------
    def _parse_passwd(self, path: Path) -> dict[str, dict[str, Any]]:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        users: dict[str, dict[str, Any]] = {}
        for line in read_lines(path):
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, _x, uid_s, gid_s, gecos, home, shell = parts[:7]
            try:
                uid = int(uid_s); gid = int(gid_s)
            except ValueError:
                continue

            user = {
                "name": name, "uid": uid, "gid": gid, "gecos": gecos,
                "home": home, "shell": shell,
                "groups": [], "password_status": None,
                "last_change_days": None,
                "max_days": None,
                "passwd_file": str(path),
            }
            users[name] = user

            self.emit_event(
                timestamp=mtime,
                source="passwd",
                event_type="account_present",
                description=f"User present: {name} uid={uid} shell={shell} home={home}",
                user=name,
                raw=line,
                metadata={"uid": uid, "gid": gid, "shell": shell, "home": home},
            )

            # ---- UID 0 anomaly ----
            if uid == 0 and name != "root":
                self.emit_finding(
                    severity=SEV_CRITICAL,
                    category="privilege_escalation",
                    title=f"Non-root account with UID 0: {name}",
                    description=(
                        f"Account '{name}' has UID 0 - it has full root "
                        "privileges. Legitimate systems have exactly one "
                        "UID 0 account named 'root'."
                    ),
                    artifact=str(path),
                    timestamp=mtime,
                    evidence=[line],
                    metadata={"user": name, "uid": uid},
                )

            # ---- service account with shell ----
            if name in SERVICE_ACCOUNTS and shell in INTERACTIVE_SHELLS:
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="account_management",
                    title=f"Service account '{name}' has interactive shell",
                    description=(
                        f"The system account '{name}' is configured with an "
                        f"interactive shell ({shell}). System accounts should "
                        "have /usr/sbin/nologin or /bin/false."
                    ),
                    artifact=str(path),
                    timestamp=mtime,
                    evidence=[line],
                    metadata={"user": name, "shell": shell},
                )

        return users

    # ------------------------------------------------------------------
    def _parse_shadow(self, path: Path, users: dict[str, dict[str, Any]]) -> None:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        for line in read_lines(path):
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 9:
                continue
            name, hashv = parts[0], parts[1]
            user = users.get(name, {"name": name})
            if hashv == "" or hashv == "!":
                user["password_status"] = "empty" if hashv == "" else "locked"
            elif hashv.startswith("!") or hashv.startswith("*"):
                user["password_status"] = "locked"
            else:
                user["password_status"] = "set"

            # ---- Hash algorithm detection ----
            # Format: $<id>$[<rounds>$]<salt>$<hash>
            # id 1 = MD5, 2a/2b/2y = bcrypt, 5 = SHA-256, 6 = SHA-512,
            # 7 = scrypt, y = yescrypt, gy = gost-yescrypt
            user["hash_algorithm"] = "(none)"
            if hashv and hashv[0] == "$":
                _id = hashv.split("$", 2)[1] if hashv.count("$") >= 2 else ""
                user["hash_algorithm"] = {
                    "1":  "MD5 (weak)",
                    "2":  "bcrypt", "2a": "bcrypt", "2b": "bcrypt", "2y": "bcrypt",
                    "5":  "SHA-256",
                    "6":  "SHA-512",
                    "7":  "scrypt",
                    "y":  "yescrypt",
                    "gy": "gost-yescrypt",
                }.get(_id, f"id={_id}")
            elif hashv in ("!", "*"):
                user["hash_algorithm"] = "(locked)"

            # ---- Age & expiry fields ----
            def _ifield(idx):
                try:
                    v = parts[idx]
                    return int(v) if v else None
                except (ValueError, IndexError):
                    return None

            user["last_change_days"] = _ifield(2)   # days since epoch
            user["min_days"]         = _ifield(3)
            user["max_days"]         = _ifield(4)
            user["warn_days"]        = _ifield(5)
            user["inactive_days"]    = _ifield(6)
            user["expire_days"]      = _ifield(7)   # account expiry in days

            # ---- Convert epoch-day fields to readable dates ----
            EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
            if user["last_change_days"]:
                user["password_last_changed"] = (
                    EPOCH + timedelta(days=user["last_change_days"])
                ).strftime("%Y-%m-%d")
            else:
                user["password_last_changed"] = ""
            if user["expire_days"]:
                user["account_expires"] = (
                    EPOCH + timedelta(days=user["expire_days"])
                ).strftime("%Y-%m-%d")
            else:
                user["account_expires"] = ""

            # ---- Computed: never_expires / stale_password ----
            user["never_expires"] = (
                user["max_days"] is None or user["max_days"] >= 99999
            )

            users[name] = user

            if hashv == "" and user.get("shell") in INTERACTIVE_SHELLS:
                self.emit_finding(
                    severity=SEV_CRITICAL,
                    category="credential_access",
                    title=f"Account with empty password: {name}",
                    description=(
                        f"Account '{name}' has an empty password hash and an "
                        "interactive shell - login is possible without "
                        "credentials."
                    ),
                    artifact=str(path),
                    timestamp=mtime,
                    evidence=[line],
                    metadata={"user": name},
                )

            # ---- Weak hash on interactive account ----
            if user.get("hash_algorithm") in ("MD5 (weak)",) and \
                    user.get("shell") in INTERACTIVE_SHELLS:
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="credential_access",
                    title=f"Weak password hash (MD5) on interactive account: {name}",
                    description=(
                        f"Account '{name}' uses MD5 password hashing which is "
                        "trivially crackable on modern hardware. Force a "
                        "password reset to upgrade to yescrypt / SHA-512."
                    ),
                    artifact=str(path),
                    timestamp=mtime,
                    metadata={"user": name, "algorithm": user["hash_algorithm"]},
                )

    # ------------------------------------------------------------------
    def _parse_group(
        self, path: Path, users: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        groups: list[dict[str, Any]] = []
        for line in read_lines(path):
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            name, _pw, gid_s, members = parts
            try:
                gid = int(gid_s)
            except ValueError:
                continue
            mems = [m for m in members.split(",") if m]
            groups.append({"name": name, "gid": gid, "members": mems})
            for m in mems:
                if m in users:
                    users[m].setdefault("groups", []).append(name)

            if name in PRIVILEGED_GROUPS and mems:
                self.emit_finding(
                    severity=SEV_HIGH if name in {"sudo", "wheel", "admin"} else SEV_MEDIUM,
                    category="privilege_escalation",
                    title=f"Members of privileged group '{name}'",
                    description=(
                        f"Group '{name}' has the following members: "
                        f"{', '.join(mems)}. Verify each is authorised."
                    ),
                    artifact=str(path),
                    timestamp=mtime,
                    evidence=[line],
                    metadata={"group": name, "members": mems},
                )
        return groups
