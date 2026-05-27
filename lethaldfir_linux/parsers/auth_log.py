"""
parsers.auth_log
================

Parses ``/var/log/auth.log`` (Debian/Ubuntu) and ``/var/log/secure``
(RHEL/CentOS/Fedora), including all rotated/compressed siblings.

Extracted events
----------------
* sshd successful logins (``Accepted password / publickey for ...``)
* sshd failed logins (``Failed password for ...``)
* sshd "Invalid user" attempts
* sudo command executions
* su switches
* useradd / usermod / groupadd / groupmod / passwd events
* CRON session opens (subset, light coverage)
* PAM session open / close

Findings raised
---------------
* **CRITICAL** SSH login as root from non-loopback IP
* **HIGH**     Brute-force pattern: >= 25 failed logins from same IP / user
* **HIGH**     Successful login immediately after failures from same IP
* **MEDIUM**   Sudo by a non-admin user
* **MEDIUM**   useradd / usermod -G adding to wheel/sudo/admin
* **LOW**      Login from new geography (best-effort, IP only - no geoip)
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

from ..core.event import SEV_CRITICAL, SEV_HIGH, SEV_LOW, SEV_MEDIUM
from ..core.utils import parse_syslog_timestamp, read_lines
from .base import BaseParser


SSHD_ACCEPTED_RE = re.compile(
    r"sshd\[\d+\]:\s+Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
SSHD_FAILED_RE = re.compile(
    r"sshd\[\d+\]:\s+Failed\s+(?P<method>\S+)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
SSHD_INVALID_RE = re.compile(
    r"sshd\[\d+\]:\s+Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)
SSHD_DISCONNECT_RE = re.compile(
    r"sshd\[\d+\]:\s+(?:Disconnected|Connection\s+closed)\s+(?:from\s+)?(?:user\s+(?P<user>\S+)\s+)?(?P<ip>\d+\.\d+\.\d+\.\d+|[0-9a-f:]+)"
)
# SSH key fingerprint — identifies WHICH key was used
SSHD_KEY_FP_RE = re.compile(
    r"sshd\[\d+\]:\s+Accepted\s+publickey\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+\d+\s+\S+:\s+(?P<keytype>\S+)\s+(?P<fp>\S+)"
)
# SSH port forwarding — lateral movement tunnels
SSHD_FORWARD_RE = re.compile(
    r"sshd\[\d+\]:\s+(?P<user>\S+)?\s*(?P<dir>Local|Remote)\s+forwarding"
)
SUDO_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target>\S+)\s+;\s+COMMAND=(?P<cmd>.+)$"
)
# sudo failure — NOT in sudoers
SUDO_FAIL_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s+:\s+.*NOT in sudoers"
)
# sudo incorrect password
SUDO_BADPW_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s+:\s+(?P<count>\d+)\s+incorrect\s+password\s+attempt"
)
SU_RE = re.compile(
    r"su(?:do)?(?:\[\d+\])?\s*:\s+\(to\s+(?P<target>\S+)\)\s+(?P<user>\S+)\s+on"
)
USERADD_RE   = re.compile(r"useradd\[\d+\]:\s+new\s+user:\s+name=(?P<user>\S+),")
USERDEL_RE   = re.compile(r"userdel\[\d+\]:\s+delete\s+user\s+'(?P<user>[^']+)'")
USERMOD_RE   = re.compile(r"usermod\[\d+\]:\s+(?P<msg>.+)")
GROUPADD_RE  = re.compile(r"groupadd\[\d+\]:\s+new\s+group:\s+name=(?P<group>\S+),")
GROUPDEL_RE  = re.compile(r"groupdel\[\d+\]:\s+(?:group\s+'(?P<group>[^']+)'\s+removed|removed\s+group\s+'(?P<group2>[^']+)')")
PASSWD_RE    = re.compile(r"passwd\[\d+\]:\s+(?:password\s+changed|pam_unix.+password\s+changed)\s+(?:for|user)?\s*(?P<user>\S*)")
PAM_OPEN_RE  = re.compile(
    r"(?P<svc>\S+)\(pam_unix\):\s+session\s+opened\s+for\s+user\s+(?P<user>\S+)"
)
# PAM auth failure — covers console, su, SSH, local
PAM_FAIL_RE  = re.compile(
    r"pam_unix\((?P<svc>[^)]+)\):\s+authentication\s+failure.*?"
    r"(?:ruser=(?P<ruser>\S*))?\s*(?:rhost=(?P<rhost>\S*))?\s*"
    r"(?:user=(?P<user>\S*))?"
)
# pkexec / polkit
PKEXEC_RE = re.compile(
    r"pkexec(?:\[\d+\])?:\s+(?P<user>\S+):\s+Executing.*\[(?P<cmd>[^\]]+)\]"
)
# systemd-logind new session
LOGIND_RE = re.compile(
    r"systemd-logind\[\d+\]:\s+New\s+session\s+(?P<session>\S+)\s+of\s+user\s+(?P<user>\S+)"
)
# SFTP subsystem request
SFTP_SUBSYS_RE = re.compile(
    r"sshd\[\d+\]:\s+subsystem\s+request\s+for\s+sftp"
)
# sftp-server file operations (open, close, remove, rename, mkdir, rmdir, stat)
SFTP_OPEN_RE = re.compile(
    r"sftp-server\[\d+\]:\s+open\s+\"(?P<path>[^\"]+)\"\s+flags\s+(?P<flags>\S+)\s+mode\s+(?P<mode>\S+)"
)
SFTP_CLOSE_RE = re.compile(
    r"sftp-server\[\d+\]:\s+close\s+\"(?P<path>[^\"]+)\"\s+bytes\s+read\s+(?P<read>\d+)\s+written\s+(?P<written>\d+)"
)
SFTP_REMOVE_RE = re.compile(
    r"sftp-server\[\d+\]:\s+remove\s+name\s+\"(?P<path>[^\"]+)\""
)
SFTP_RENAME_RE = re.compile(
    r"sftp-server\[\d+\]:\s+rename\s+old\s+\"(?P<old>[^\"]+)\"\s+new\s+\"(?P<new>[^\"]+)\""
)
SFTP_MKDIR_RE = re.compile(
    r"sftp-server\[\d+\]:\s+mkdir\s+name\s+\"(?P<path>[^\"]+)\""
)
SFTP_SESSION_RE = re.compile(
    r"sftp-server\[\d+\]:\s+session\s+(?P<action>opened|closed)\s+for\s+local\s+user\s+(?P<user>\S+)"
)

# Sensitive paths that trigger HIGH findings when accessed via SFTP
SENSITIVE_PATHS = (
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/.ssh/", "/id_rsa", "/id_ed25519", "/authorized_keys",
    "/etc/gshadow", "/root/",
)


PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "root", "adm"}


class AuthLogParser(BaseParser):
    name = "auth_log"

    def run(self) -> None:
        files = self.finder.find_log_family("auth.log") + self.finder.find_log_family("secure")
        # de-duplicate
        seen: set[Path] = set()
        files = [f for f in files if not (f in seen or seen.add(f))]

        # accumulators for cross-line correlation
        failures: dict[str, list] = defaultdict(list)
        accepted_index: list = []

        # per-parser CSV records
        ssh_records: list[dict] = []
        sudo_records: list[dict] = []
        account_records: list[dict] = []
        sftp_records: list[dict] = []

        for f in files:
            self.note_file(f)
            self._parse_one(f, failures, accepted_index,
                            ssh_records, sudo_records, account_records,
                            sftp_records)

        # post-pass: brute-force detection
        for ip, entries in failures.items():
            if len(entries) >= 25:
                users = sorted({u for _, u in entries})
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="credential_access",
                    title=f"SSH brute-force pattern from {ip}",
                    description=(
                        f"{len(entries)} failed SSH authentications observed "
                        f"from {ip} targeting {len(users)} username(s)."
                    ),
                    artifact="auth.log/secure",
                    evidence=[f"users: {', '.join(users[:10])}"],
                    metadata={"ip": ip, "count": len(entries), "users": users},
                )

        # post-pass: success-after-failures correlation
        for ts, user, ip in accepted_index:
            recent_fails = [
                e for e in failures.get(ip, [])
                if 0 <= (ts - e[0]).total_seconds() <= 600
            ]
            if len(recent_fails) >= 5:
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="credential_access",
                    title=f"Successful SSH login after {len(recent_fails)} failures from {ip}",
                    description=(
                        f"User {user} authenticated successfully from {ip} after "
                        f"{len(recent_fails)} failed attempts in the prior 10 minutes."
                    ),
                    artifact="auth.log/secure",
                    timestamp=ts,
                    metadata={"ip": ip, "user": user},
                )

        # Write per-parser CSVs
        self.write_csv("auth_ssh_logins.csv", ssh_records,
                       ["timestamp", "event", "user", "ip", "method",
                        "port", "key_fingerprint", "source_file"])
        self.write_csv("auth_sudo_commands.csv", sudo_records,
                       ["timestamp", "event", "user", "target_user",
                        "tty", "pwd", "command", "source_file"])
        self.write_csv("auth_account_changes.csv", account_records,
                       ["timestamp", "event", "user", "detail", "source_file"])
        self.write_csv("auth_sftp_activity.csv", sftp_records,
                       ["timestamp", "operation", "user", "path",
                        "flags", "bytes_read", "bytes_written", "source_file"])

    def _parse_one(self, path: Path, failures: dict, accepted_index: list,
                   ssh_records: list, sudo_records: list,
                   account_records: list, sftp_records: list) -> None:
        for line in read_lines(path):
            ts = parse_syslog_timestamp(line)
            if ts is None:
                continue
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")

            # ---- sshd accepted ----
            m = SSHD_ACCEPTED_RE.search(line)
            if m:
                user = m["user"]
                ip = m["ip"]
                method = m["method"]
                # Try to extract key fingerprint
                key_fp = ""
                km = SSHD_KEY_FP_RE.search(line)
                if km:
                    key_fp = f"{km['keytype']}:{km['fp']}"
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="ssh_login_success",
                    description=f"SSH login success: user={user} ip={ip} method={method}"
                               + (f" key={key_fp}" if key_fp else ""),
                    user=user,
                    raw=line,
                    metadata={"ip": ip, "method": method, "port": m["port"],
                              "key_fingerprint": key_fp},
                )
                ssh_records.append({
                    "timestamp": ts_str, "event": "SUCCESS", "user": user,
                    "ip": ip, "method": method, "port": m["port"],
                    "key_fingerprint": key_fp, "source_file": str(path),
                })
                accepted_index.append((ts, user, ip))
                if user == "root" and ip not in ("127.0.0.1", "::1"):
                    self.emit_finding(
                        severity=SEV_CRITICAL,
                        category="credential_access",
                        title=f"Direct root SSH login from {ip}",
                        description=(
                            f"Successful interactive root SSH login from {ip} via {method}. "
                            "Direct root logins should be disabled (PermitRootLogin no)."
                        ),
                        artifact=str(path),
                        timestamp=ts,
                        evidence=[line.strip()],
                        metadata={"user": user, "ip": ip, "method": method},
                    )
                continue

            # ---- sshd failed ----
            m = SSHD_FAILED_RE.search(line)
            if m:
                user = m["user"]
                ip = m["ip"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="ssh_login_failed",
                    description=f"SSH login failed: user={user} ip={ip}",
                    user=user,
                    raw=line,
                    metadata={"ip": ip, "method": m["method"]},
                )
                ssh_records.append({
                    "timestamp": ts_str, "event": "FAILED", "user": user,
                    "ip": ip, "method": m["method"], "port": m["port"],
                    "key_fingerprint": "", "source_file": str(path),
                })
                failures[ip].append((ts, user))
                continue

            # ---- sshd invalid user ----
            m = SSHD_INVALID_RE.search(line)
            if m:
                user = m["user"]
                ip = m["ip"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="ssh_invalid_user",
                    description=f"SSH invalid user: user={user} ip={ip}",
                    user=user,
                    raw=line,
                    metadata={"ip": ip},
                )
                ssh_records.append({
                    "timestamp": ts_str, "event": "INVALID_USER", "user": user,
                    "ip": ip, "method": "", "port": "",
                    "key_fingerprint": "", "source_file": str(path),
                })
                failures[ip].append((ts, user))
                continue

            # ---- SSH port forwarding ----
            m = SSHD_FORWARD_RE.search(line)
            if m:
                direction = m["dir"]
                fwd_user = m.group("user") or ""
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="ssh_port_forward",
                    description=f"SSH {direction} forwarding{' by ' + fwd_user if fwd_user else ''}",
                    user=fwd_user or None,
                    raw=line,
                )
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="lateral_movement",
                    title=f"SSH {direction} port forwarding detected",
                    description=(
                        f"SSH {direction.lower()} port forwarding was set up. "
                        "This can be used for tunneling, pivoting, or "
                        "bypassing network controls."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()],
                )
                continue

            # ---- sudo command ----
            m = SUDO_RE.search(line)
            if m:
                user = m["user"]
                target = m["target"]
                cmd = m["cmd"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="sudo_command",
                    description=f"sudo: {user} -> {target}: {cmd}",
                    user=user,
                    raw=line,
                    metadata={"target": target, "command": cmd, "tty": m["tty"], "pwd": m["pwd"]},
                )
                sudo_records.append({
                    "timestamp": ts_str, "event": "SUDO_OK", "user": user,
                    "target_user": target, "tty": m["tty"], "pwd": m["pwd"],
                    "command": cmd, "source_file": str(path),
                })
                continue

            # ---- sudo NOT in sudoers ----
            m = SUDO_FAIL_RE.search(line)
            if m:
                user = m["user"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="sudo_not_in_sudoers",
                    description=f"sudo: {user} NOT in sudoers",
                    user=user,
                    raw=line,
                )
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="privilege_escalation",
                    title=f"sudo attempt by unauthorized user: {user}",
                    description=(
                        f"User '{user}' attempted to use sudo but is NOT in "
                        "the sudoers file. This is a privilege escalation "
                        "attempt or misconfiguration."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()],
                    metadata={"user": user},
                )
                sudo_records.append({
                    "timestamp": ts_str, "event": "NOT_IN_SUDOERS",
                    "user": user, "target_user": "", "tty": "",
                    "pwd": "", "command": "", "source_file": str(path),
                })
                continue

            # ---- sudo incorrect password ----
            m = SUDO_BADPW_RE.search(line)
            if m:
                user = m["user"]
                count = m["count"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="sudo_bad_password",
                    description=f"sudo: {user} had {count} incorrect password attempts",
                    user=user,
                    raw=line,
                )
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="credential_access",
                    title=f"sudo incorrect password: {user} ({count} attempts)",
                    description=(
                        f"User '{user}' entered {count} incorrect password(s) "
                        "for sudo. May indicate credential guessing."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()],
                )
                continue

            # ---- PAM auth failure ----
            m = PAM_FAIL_RE.search(line)
            if m:
                svc = m["svc"]
                pam_user = m.group("user") or m.group("ruser") or ""
                rhost = m.group("rhost") or ""
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="pam_auth_failure",
                    description=f"PAM auth failure: svc={svc} user={pam_user} rhost={rhost}",
                    user=pam_user or None,
                    raw=line,
                    metadata={"service": svc, "rhost": rhost},
                )
                continue

            # ---- su ----
            m = SU_RE.search(line)
            if m:
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="su_switch",
                    description=f"su: {m['user']} -> {m['target']}",
                    user=m["user"],
                    raw=line,
                    metadata={"target": m["target"]},
                )
                continue

            # ---- account changes ----
            m = USERADD_RE.search(line)
            if m:
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="user_added",
                    description=f"User added: {m['user']}",
                    user=m["user"],
                    raw=line,
                )
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="account_management",
                    title=f"New user account created: {m['user']}",
                    description=(
                        "A new local user account was created. Confirm whether this "
                        "matches a known change ticket or onboarding workflow."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()],
                )
                account_records.append({
                    "timestamp": ts_str, "event": "USER_ADDED",
                    "user": m["user"], "detail": line.strip(),
                    "source_file": str(path),
                })
                continue

            # ---- userdel ----
            m = USERDEL_RE.search(line)
            if m:
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="user_deleted",
                    description=f"User deleted: {m['user']}",
                    user=m["user"],
                    raw=line,
                )
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="account_management",
                    title=f"User account deleted: {m['user']}",
                    description=(
                        f"User account '{m['user']}' was deleted. Account "
                        "deletion can be an anti-forensic cleanup technique."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()],
                )
                account_records.append({
                    "timestamp": ts_str, "event": "USER_DELETED",
                    "user": m["user"], "detail": line.strip(),
                    "source_file": str(path),
                })
                continue

            m = USERMOD_RE.search(line)
            if m:
                msg = m["msg"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="user_modified",
                    description=f"usermod: {msg}",
                    raw=line,
                )
                low = msg.lower()
                if any(g in low for g in PRIVILEGED_GROUPS):
                    self.emit_finding(
                        severity=SEV_HIGH,
                        category="privilege_escalation",
                        title="User added to privileged group",
                        description=(
                            "A usermod event referenced a privileged group (sudo, "
                            "wheel, admin, etc.). Review whether this matches an "
                            "approved change."
                        ),
                        artifact=str(path),
                        timestamp=ts,
                        evidence=[line.strip()],
                    )
                account_records.append({
                    "timestamp": ts_str, "event": "USER_MODIFIED",
                    "user": "", "detail": msg,
                    "source_file": str(path),
                })
                continue

            m = GROUPADD_RE.search(line)
            if m:
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="group_added",
                    description=f"Group added: {m['group']}",
                    raw=line,
                )
                continue

            # ---- groupdel ----
            m = GROUPDEL_RE.search(line)
            if m:
                group = m.group("group") or m.group("group2") or ""
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="group_deleted",
                    description=f"Group deleted: {group}",
                    raw=line,
                )
                continue

            m = PASSWD_RE.search(line)
            if m:
                user = m["user"] or "(unknown)"
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="password_changed",
                    description=f"Password changed for {user}",
                    user=user,
                    raw=line,
                )
                account_records.append({
                    "timestamp": ts_str, "event": "PASSWORD_CHANGED",
                    "user": user, "detail": "",
                    "source_file": str(path),
                })
                continue

            # ---- pkexec / polkit ----
            m = PKEXEC_RE.search(line)
            if m:
                user = m["user"]
                cmd = m["cmd"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="pkexec",
                    description=f"pkexec: {user} executed {cmd}",
                    user=user,
                    raw=line,
                    metadata={"command": cmd},
                )
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="execution",
                    title=f"pkexec execution by {user}",
                    description=(
                        f"User '{user}' executed a command via pkexec (polkit). "
                        "Review for CVE-2021-4034 (PwnKit) exploitation or "
                        "unauthorized privilege escalation."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()],
                )
                continue

            # ---- systemd-logind new session ----
            m = LOGIND_RE.search(line)
            if m:
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="logind_new_session",
                    description=f"New session {m['session']} for user {m['user']}",
                    user=m["user"],
                    raw=line,
                    metadata={"session_id": m["session"]},
                )
                continue

            m = PAM_OPEN_RE.search(line)
            if m:
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="pam_session_open",
                    description=f"PAM session opened: svc={m['svc']} user={m['user']}",
                    user=m["user"],
                    raw=line,
                )
                continue

            # ---- SFTP subsystem request ----
            m = SFTP_SUBSYS_RE.search(line)
            if m:
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="sftp_subsystem_request",
                    description="SFTP subsystem requested",
                    raw=line,
                )
                continue

            # ---- SFTP session open/close ----
            m = SFTP_SESSION_RE.search(line)
            if m:
                action = m["action"]
                sftp_user = m["user"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type=f"sftp_session_{action}",
                    description=f"SFTP session {action} for {sftp_user}",
                    user=sftp_user,
                    raw=line,
                )
                sftp_records.append({
                    "timestamp": ts_str, "operation": f"SESSION_{action.upper()}",
                    "user": sftp_user, "path": "", "flags": "",
                    "bytes_read": "", "bytes_written": "",
                    "source_file": str(path),
                })
                continue

            # ---- SFTP file close (has bytes transferred) ----
            m = SFTP_CLOSE_RE.search(line)
            if m:
                fpath = m["path"]
                bread = m["read"]
                bwritten = m["written"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="sftp_close",
                    description=f"SFTP close: {fpath} (read={bread} written={bwritten})",
                    raw=line,
                    metadata={"path": fpath, "bytes_read": bread,
                              "bytes_written": bwritten},
                )
                sftp_records.append({
                    "timestamp": ts_str, "operation": "CLOSE",
                    "user": "", "path": fpath, "flags": "",
                    "bytes_read": bread, "bytes_written": bwritten,
                    "source_file": str(path),
                })
                # Alert on sensitive file access
                low_path = fpath.lower()
                if any(s in low_path for s in SENSITIVE_PATHS):
                    self.emit_finding(
                        severity=SEV_HIGH,
                        category="data_exfiltration",
                        title=f"Sensitive file accessed via SFTP: {fpath}",
                        description=(
                            f"File '{fpath}' was accessed via SFTP with "
                            f"{bread} bytes read and {bwritten} bytes written. "
                            "This file contains sensitive data."
                        ),
                        artifact=str(path),
                        timestamp=ts,
                        evidence=[line.strip()],
                        metadata={"sftp_path": fpath, "bytes_read": bread,
                                  "bytes_written": bwritten},
                    )
                continue

            # ---- SFTP file open ----
            m = SFTP_OPEN_RE.search(line)
            if m:
                fpath = m["path"]
                flags = m["flags"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="sftp_open",
                    description=f"SFTP open: {fpath} flags={flags}",
                    raw=line,
                    metadata={"path": fpath, "flags": flags},
                )
                sftp_records.append({
                    "timestamp": ts_str, "operation": "OPEN",
                    "user": "", "path": fpath, "flags": flags,
                    "bytes_read": "", "bytes_written": "",
                    "source_file": str(path),
                })
                continue

            # ---- SFTP remove ----
            m = SFTP_REMOVE_RE.search(line)
            if m:
                fpath = m["path"]
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="sftp_remove",
                    description=f"SFTP remove: {fpath}",
                    raw=line,
                    metadata={"path": fpath},
                )
                sftp_records.append({
                    "timestamp": ts_str, "operation": "REMOVE",
                    "user": "", "path": fpath, "flags": "",
                    "bytes_read": "", "bytes_written": "",
                    "source_file": str(path),
                })
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="file_modification",
                    title=f"File deleted via SFTP: {fpath}",
                    description=(
                        f"File '{fpath}' was deleted via SFTP. Remote file "
                        "deletion may indicate anti-forensic activity."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()],
                )
                continue

            # ---- SFTP rename ----
            m = SFTP_RENAME_RE.search(line)
            if m:
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="sftp_rename",
                    description=f"SFTP rename: {m['old']} -> {m['new']}",
                    raw=line,
                    metadata={"old": m["old"], "new": m["new"]},
                )
                sftp_records.append({
                    "timestamp": ts_str, "operation": "RENAME",
                    "user": "", "path": f"{m['old']} -> {m['new']}",
                    "flags": "", "bytes_read": "", "bytes_written": "",
                    "source_file": str(path),
                })
                continue

            # ---- SFTP mkdir ----
            m = SFTP_MKDIR_RE.search(line)
            if m:
                self.emit_event(
                    timestamp=ts,
                    source="auth.log",
                    event_type="sftp_mkdir",
                    description=f"SFTP mkdir: {m['path']}",
                    raw=line,
                    metadata={"path": m["path"]},
                )
                sftp_records.append({
                    "timestamp": ts_str, "operation": "MKDIR",
                    "user": "", "path": m["path"], "flags": "",
                    "bytes_read": "", "bytes_written": "",
                    "source_file": str(path),
                })
                continue
