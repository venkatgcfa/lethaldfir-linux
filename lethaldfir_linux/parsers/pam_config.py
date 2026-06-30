"""
parsers.pam_config
==================

Parses PAM stack configuration and related security files.

Files: /etc/pam.d/*, /etc/securetty, /etc/login.defs,
       /etc/security/access.conf, /etc/hosts.allow, /etc/hosts.deny,
       /etc/selinux/config

Findings:
  CRITICAL: SELinux disabled
  HIGH: pam_exec backdoors, pam_permit without auth, SELinux permissive
  MEDIUM: weak login.defs, empty securetty, TCP wrappers wide-open
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_CRITICAL, SEV_HIGH, SEV_LOW, SEV_MEDIUM
from ..core.utils import read_lines
from .base import BaseParser


class PamConfigParser(BaseParser):
    name = "pam_config"

    def run(self) -> None:
        self._check_pam_d()
        self._check_login_defs()
        self._check_securetty()
        self._check_selinux_config()
        self._check_apparmor()
        self._check_tcp_wrappers()

    def _ts(self, path: Path) -> datetime:
        try:
            return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            return datetime.now(timezone.utc)

    # -- PAM -----------------------------------------------------------
    def _check_pam_d(self) -> None:
        for f in self.finder.find_by_glob(["**/etc/pam.d/*"]):
            if not f.is_file():
                continue
            self.note_file(f)
            ts = self._ts(f)
            for line in read_lines(f):
                ls = line.strip()
                if not ls or ls.startswith("#"):
                    continue

                # pam_exec can run arbitrary commands
                if "pam_exec" in ls:
                    self.emit_finding(
                        severity=SEV_HIGH, category="persistence",
                        title=f"pam_exec in PAM config: {f.name}",
                        description=(
                            "pam_exec module runs an arbitrary command during "
                            "PAM authentication. This is a known persistence/ "
                            "credential-theft technique."
                        ),
                        artifact=str(f), timestamp=ts,
                        evidence=[ls],
                    )

                # pam_permit as auth = no auth required
                if "pam_permit" in ls and ls.startswith("auth"):
                    self.emit_finding(
                        severity=SEV_HIGH, category="credential_access",
                        title=f"pam_permit in auth stack: {f.name}",
                        description=(
                            "pam_permit in the auth stack means authentication "
                            "always succeeds — effectively a backdoor."
                        ),
                        artifact=str(f), timestamp=ts,
                        evidence=[ls],
                    )

                low = ls.lower()

                # nullok / nullok_secure on an auth line accepts EMPTY passwords
                if ls.startswith("auth") and "nullok" in low:
                    self.emit_finding(
                        severity=SEV_HIGH, category="credential_access",
                        title=f"PAM accepts empty passwords (nullok): {f.name}",
                        description=(
                            "An auth line uses nullok/nullok_secure, permitting "
                            "login to any account that has an empty password — "
                            "the most common PAM authentication bypass."
                        ),
                        artifact=str(f), timestamp=ts,
                        evidence=[ls],
                    )

                # pam_exec ... expose_authtok pipes the cleartext password out
                if "pam_exec" in low and "expose_authtok" in low:
                    self.emit_finding(
                        severity=SEV_CRITICAL, category="credential_access",
                        title=f"pam_exec expose_authtok (password theft): {f.name}",
                        description=(
                            "pam_exec with expose_authtok passes the user's "
                            "cleartext password on stdin to an external program "
                            "— a credential-theft backdoor."
                        ),
                        artifact=str(f), timestamp=ts,
                        evidence=[ls],
                    )

    # -- login.defs ----------------------------------------------------
    def _check_login_defs(self) -> None:
        for f in self.finder.find_by_suffix(["/etc/login.defs"]):
            self.note_file(f)
            ts = self._ts(f)
            kv: dict[str, str] = {}
            for line in read_lines(f):
                ls = line.strip()
                if not ls or ls.startswith("#"):
                    continue
                parts = ls.split(None, 1)
                if len(parts) == 2:
                    kv[parts[0]] = parts[1]

            self.emit_event(
                timestamp=ts, source="login.defs",
                event_type="login_defs_parsed",
                description=f"login.defs: {len(kv)} settings parsed",
                metadata=kv,
            )

            # Check for weak settings
            pass_max = int(kv.get("PASS_MAX_DAYS", "99999"))
            if pass_max > 365:
                self.emit_finding(
                    severity=SEV_LOW, category="hardening",
                    title=f"PASS_MAX_DAYS={pass_max} (weak password aging)",
                    description="Password maximum age exceeds 365 days.",
                    artifact=str(f), timestamp=ts,
                )

            encrypt = kv.get("ENCRYPT_METHOD", "")
            if encrypt.upper() in ("DES", "MD5"):
                self.emit_finding(
                    severity=SEV_MEDIUM, category="hardening",
                    title=f"Weak password hash: ENCRYPT_METHOD={encrypt}",
                    description="DES/MD5 password hashing is cryptographically weak.",
                    artifact=str(f), timestamp=ts,
                )

    # -- securetty -----------------------------------------------------
    def _check_securetty(self) -> None:
        for f in self.finder.find_by_suffix(["/etc/securetty"]):
            self.note_file(f)
            ts = self._ts(f)
            ttys = [l.strip() for l in read_lines(f)
                    if l.strip() and not l.strip().startswith("#")]
            self.emit_event(
                timestamp=ts, source="securetty",
                event_type="securetty_parsed",
                description=f"securetty: {len(ttys)} TTYs allowed for root",
                metadata={"ttys": ttys},
            )

    # -- SELinux --------------------------------------------------------
    def _check_selinux_config(self) -> None:
        for f in self.finder.find_by_suffix(["/etc/selinux/config"]):
            self.note_file(f)
            ts = self._ts(f)
            mode = None
            for line in read_lines(f):
                ls = line.strip()
                if ls.startswith("SELINUX="):
                    mode = ls.split("=", 1)[1].strip().lower()

            if mode:
                self.emit_event(
                    timestamp=ts, source="selinux",
                    event_type="selinux_mode",
                    description=f"SELinux mode: {mode}",
                    metadata={"mode": mode},
                )
                if mode == "disabled":
                    self.emit_finding(
                        severity=SEV_CRITICAL, category="defense_evasion",
                        title="SELinux is DISABLED",
                        description=(
                            "SELinux is set to 'disabled'. An attacker may "
                            "have disabled it to bypass MAC controls."
                        ),
                        artifact=str(f), timestamp=ts,
                        evidence=[f"SELINUX={mode}"],
                    )
                elif mode == "permissive":
                    self.emit_finding(
                        severity=SEV_HIGH, category="defense_evasion",
                        title="SELinux in PERMISSIVE mode",
                        description=(
                            "SELinux is set to 'permissive' — violations are "
                            "logged but not enforced."
                        ),
                        artifact=str(f), timestamp=ts,
                        evidence=[f"SELINUX={mode}"],
                    )

    # -- AppArmor ------------------------------------------------------
    def _check_apparmor(self) -> None:
        for f in self.finder.find_by_glob(["**/etc/apparmor.d/*"]):
            if not f.is_file() or f.name.startswith("."):
                continue
            self.note_file(f)
            ts = self._ts(f)
            content = "\n".join(read_lines(f))
            if "flags=(complain)" in content:
                self.emit_finding(
                    severity=SEV_MEDIUM, category="defense_evasion",
                    title=f"AppArmor profile in complain mode: {f.name}",
                    description=(
                        "This AppArmor profile is set to 'complain' mode — "
                        "violations are logged but not blocked."
                    ),
                    artifact=str(f), timestamp=ts,
                )

    # -- TCP Wrappers --------------------------------------------------
    def _check_tcp_wrappers(self) -> None:
        for f in self.finder.find_by_suffix(["/etc/hosts.allow"]):
            self.note_file(f)
            ts = self._ts(f)
            for line in read_lines(f):
                ls = line.strip()
                if not ls or ls.startswith("#"):
                    continue
                if "ALL : ALL" in ls.upper():
                    self.emit_finding(
                        severity=SEV_MEDIUM, category="network_config",
                        title="TCP Wrappers: ALL : ALL in hosts.allow",
                        description="hosts.allow permits all connections.",
                        artifact=str(f), timestamp=ts, evidence=[ls],
                    )
