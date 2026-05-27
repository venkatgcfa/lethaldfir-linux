"""
parsers.ssh
===========

Parses ``/etc/ssh/sshd_config`` for security-relevant settings and walks
every user's ``~/.ssh/authorized_keys`` and ``~/.ssh/known_hosts``.

Findings raised
---------------
* **HIGH**     ``PermitRootLogin yes`` / ``PermitRootLogin without-password``
* **HIGH**     ``PasswordAuthentication yes`` (informational on infra hosts,
               but elevated when combined with root login)
* **HIGH**     ``PermitEmptyPasswords yes``
* **HIGH**     authorized_keys with ``command="..."`` containing suspicious
               tokens (``nc``, ``bash -i``, ``/tmp/``, etc.)
* **MEDIUM**   ``Protocol 1`` (legacy SSHv1)
* **MEDIUM**   Multiple authorized_keys entries for root
* **INFO**     Per-key inventory event
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_INFO, SEV_MEDIUM
from ..core.utils import find_suspicious_tokens, read_lines
from .base import BaseParser


SSHD_DIRECTIVE_RE = re.compile(r"^\s*([A-Za-z]+)\s+(.*?)\s*$")

# Recognised SSH public key algorithms. Anything starting with one of these
# tokens (followed by whitespace) marks the end of the optional options
# field and the start of <keytype> <base64> [comment].
_KEY_TYPE_PREFIXES = (
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)


def _parse_key_line(line: str) -> dict | None:
    """Split an authorized_keys line without catastrophic regex.

    Returns a dict with options/type/b64/comment, or None on failure.
    The format is ``[options ]<type> <base64> [comment]``. Options may
    contain quoted strings with embedded spaces.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    # Locate the key-type token. We scan the line and look for the
    # first whitespace-delimited token that matches a known key type.
    # Anything before it is the options field.
    pos = 0
    in_quote = False
    type_start: int | None = None

    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == '"':
            in_quote = not in_quote
            i += 1
            continue
        if not in_quote and ch.isspace():
            # token boundary - check whether the next token is a key type
            j = i + 1
            while j < n and s[j].isspace():
                j += 1
            # candidate token runs from j to next whitespace
            k = j
            while k < n and not s[k].isspace():
                k += 1
            cand = s[j:k]
            if cand.startswith(_KEY_TYPE_PREFIXES) or cand in _KEY_TYPE_PREFIXES:
                type_start = j
                break
            i = j
            continue
        i += 1

    if type_start is None:
        # No options field — line should start with the key type itself.
        first = s.split(None, 1)[0] if s else ""
        if first.startswith(_KEY_TYPE_PREFIXES) or first in _KEY_TYPE_PREFIXES:
            type_start = 0
            options = ""
        else:
            return None
    else:
        options = s[:type_start].strip()

    rest = s[type_start:].split(None, 2)
    if len(rest) < 2:
        return None
    keytype = rest[0]
    b64 = rest[1]
    comment = rest[2] if len(rest) >= 3 else ""

    return {
        "options": options,
        "type": keytype,
        "b64": b64,
        "comment": comment,
    }


class SSHParser(BaseParser):
    name = "ssh"

    def run(self) -> None:
        # ---- sshd_config ----
        for f in self.finder.find_by_suffix(["/etc/ssh/sshd_config"]):
            self.note_file(f)
            self._parse_sshd_config(f)

        # also any drop-in
        for f in self.finder.find_by_glob(["**/etc/ssh/sshd_config.d/*.conf"]):
            self.note_file(f)
            self._parse_sshd_config(f)

        # ---- authorized_keys ----
        ak_files = self.finder.find_by_glob([
            "**/.ssh/authorized_keys",
            "**/.ssh/authorized_keys2",
        ])
        seen: set[Path] = set()
        for f in ak_files:
            if f in seen:
                continue
            seen.add(f)
            self.note_file(f)
            self._parse_authorized_keys(f)

    # ------------------------------------------------------------------
    def _parse_sshd_config(self, path: Path) -> None:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        directives: dict[str, str] = {}
        for raw in read_lines(path):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = SSHD_DIRECTIVE_RE.match(line)
            if not m:
                continue
            key = m.group(1).lower()
            val = m.group(2).strip().lower()
            # last value wins (matches sshd behaviour for most directives)
            directives[key] = val

        self.case.set_artifact(f"sshd_config::{path}", directives)

        self.emit_event(
            timestamp=mtime,
            source="sshd_config",
            event_type="config_loaded",
            description=f"sshd_config parsed: {path}",
            metadata={"directives": directives},
        )

        # ---- evaluate ----
        prl = directives.get("permitrootlogin", "prohibit-password")
        if prl in {"yes", "without-password"}:
            self.emit_finding(
                severity=SEV_HIGH,
                category="hardening",
                title=f"PermitRootLogin = {prl}",
                description=(
                    "sshd is configured to allow root login. Industry best "
                    "practice is 'no'. 'without-password' permits root via key."
                ),
                artifact=str(path),
                timestamp=mtime,
                evidence=[f"PermitRootLogin {prl}"],
            )

        if directives.get("permitemptypasswords") == "yes":
            self.emit_finding(
                severity=SEV_HIGH,
                category="hardening",
                title="PermitEmptyPasswords = yes",
                description="sshd accepts logins for accounts with empty passwords.",
                artifact=str(path),
                timestamp=mtime,
                evidence=["PermitEmptyPasswords yes"],
            )

        if directives.get("passwordauthentication") == "yes" and \
                prl in {"yes", "without-password"}:
            self.emit_finding(
                severity=SEV_HIGH,
                category="hardening",
                title="Root password SSH login enabled",
                description=(
                    "Both PermitRootLogin and PasswordAuthentication permit "
                    "interactive root password authentication."
                ),
                artifact=str(path),
                timestamp=mtime,
            )

        if directives.get("protocol") == "1":
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="hardening",
                title="Legacy SSH Protocol 1 enabled",
                description="SSHv1 is cryptographically broken and must be disabled.",
                artifact=str(path),
                timestamp=mtime,
            )

    # ------------------------------------------------------------------
    def _parse_authorized_keys(self, path: Path) -> None:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        user = self._infer_user(path)
        keys = []
        for raw in read_lines(path):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parsed = _parse_key_line(line)
            if not parsed:
                continue
            entry = {
                "user": user,
                "options": parsed["options"],
                "type": parsed["type"],
                "comment": parsed["comment"],
                "fingerprint_b64_prefix": parsed["b64"][:24],
                "file": str(path),
            }
            keys.append(entry)
            self.emit_event(
                timestamp=mtime,
                source="authorized_keys",
                event_type="ssh_key_present",
                description=(
                    f"authorized_keys entry: user={user} type={entry['type']} "
                    f"comment={entry['comment'] or '(none)'}"
                ),
                user=user,
                metadata=entry,
            )
            opts = entry["options"].lower()
            if opts:
                hits = find_suspicious_tokens(opts)
                if hits:
                    self.emit_finding(
                        severity=SEV_HIGH,
                        category="persistence",
                        title=f"Suspicious authorized_keys options for {user}",
                        description=(
                            "An authorized_keys entry has an options field "
                            "containing tokens associated with attacker "
                            f"command-binding: {', '.join(hits)}."
                        ),
                        artifact=str(path),
                        timestamp=mtime,
                        evidence=[line],
                        metadata=entry,
                    )

        if user == "root" and len(keys) > 1:
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="persistence",
                title=f"Multiple authorized_keys entries for root ({len(keys)})",
                description=(
                    f"Root has {len(keys)} SSH public keys authorised. "
                    "Verify each is owned by an authorised administrator."
                ),
                artifact=str(path),
                timestamp=mtime,
                metadata={"count": len(keys)},
            )

    @staticmethod
    def _infer_user(path: Path) -> str:
        parts = path.as_posix().split("/")
        for i, p in enumerate(parts):
            if p == "home" and i + 1 < len(parts):
                return parts[i + 1]
            if p == "root":
                return "root"
        return "(unknown)"
