"""
parsers.web_error_logs
======================

Parses Apache and Nginx **error** logs (distinct from the access-log
parser ``web_logs``).

Files covered
-------------
* ``/var/log/apache2/error.log``    (Debian/Ubuntu)
* ``/var/log/httpd/error_log``      (RHEL/CentOS)
* ``/var/log/nginx/error.log``

Apache error format::
    [Day Mon DD HH:MM:SS.usec YYYY] [module:level] [pid N] [client IP:port] AH01630: message

Nginx error format::
    YYYY/MM/DD HH:MM:SS [level] PID#TID: *N message

Findings raised
---------------
* **HIGH**     PHP errors referencing ``/tmp``, ``/dev/shm`` or webshell paths
* **HIGH**     mod_security / ModSecurity rule trigger
* **MEDIUM**   Repeated permission-denied errors (possible traversal)
* **MEDIUM**   Segfault in web server (possible exploitation)
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import read_lines
from .base import BaseParser


# Apache error.log timestamp: [Sun Sep 01 12:34:56.123456 2024]
APACHE_ERR_RE = re.compile(
    r"^\[(?P<ts>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*\s+\d{4})\]"
    r"\s+\[(?P<module>[^:]+):(?P<level>\S+)\]"
    r"(?:\s+\[pid\s+\d+[^\]]*\])?"
    r"(?:\s+\[client\s+(?P<client>[^\]]+)\])?"
    r"\s*(?P<msg>.*)"
)

# Nginx error.log timestamp: 2024/09/01 12:34:56
NGINX_ERR_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+\[(?P<level>\w+)\]"
    r"\s+(?P<pid>\d+)#(?P<tid>\d+):"
    r"\s*(?:\*\d+\s+)?(?P<msg>.*)"
)

# Suspicious patterns in error messages
WEBSHELL_INDICATORS = (
    "/tmp/", "/dev/shm/", "/var/tmp/",
    "wso.php", "c99.php", "r57.php", "cmd.php", "shell.php",
    "b374k", "weevely", "phpspy",
)
MODSEC_RE = re.compile(r"ModSecurity|mod_security|SecRule", re.IGNORECASE)


class WebErrorLogsParser(BaseParser):
    name = "web_error_logs"

    def run(self) -> None:
        files = self.finder.find_by_glob([
            "**/var/log/apache2/error.log*",
            "**/var/log/httpd/error_log*",
            "**/var/log/nginx/error.log*",
        ])
        seen: set[Path] = set()
        files = [f for f in files if not (f in seen or seen.add(f))]

        permission_counter: Counter = Counter()

        for f in files:
            self.note_file(f)
            self._parse_one(f, permission_counter)

        # Post-pass: excessive permission denied
        for source, count in permission_counter.items():
            if count >= 50:
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="exploitation",
                    title=f"Excessive permission-denied errors: {count}",
                    description=(
                        f"Web server error log '{source}' contains {count} "
                        "permission-denied errors, potentially indicating "
                        "directory traversal or brute-force path discovery."
                    ),
                    artifact=source,
                    metadata={"count": count},
                )

    def _parse_one(self, path: Path, perm_counter: Counter) -> None:
        for line in read_lines(path):
            ts, level, msg, client = self._parse_line(line)
            if ts is None or not msg:
                continue

            self.emit_event(
                timestamp=ts,
                source="web_error",
                event_type=f"web_error_{level or 'unknown'}",
                description=f"{level or '?'}: {msg[:300]}",
                metadata={
                    "level": level, "client": client or "",
                    "file": str(path),
                },
                raw=line,
            )

            low = msg.lower()

            # ---- PHP errors from suspicious paths ----
            if "php" in low:
                for indicator in WEBSHELL_INDICATORS:
                    if indicator in low:
                        self.emit_finding(
                            severity=SEV_HIGH,
                            category="execution",
                            title="PHP error referencing suspicious path",
                            description=(
                                f"A PHP error in the web error log references "
                                f"'{indicator}', which may indicate webshell "
                                "execution or a dropped payload."
                            ),
                            artifact=str(path),
                            timestamp=ts,
                            evidence=[line.strip()[:500]],
                            metadata={"client": client or ""},
                        )
                        break

            # ---- ModSecurity blocks ----
            if MODSEC_RE.search(msg):
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="exploitation",
                    title="ModSecurity rule triggered",
                    description=(
                        "The web application firewall (ModSecurity) blocked "
                        "or logged a request. Review the rule ID and payload."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()[:500]],
                    metadata={"client": client or ""},
                )

            # ---- segfault ----
            if "segfault" in low or "signal 11" in low:
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="exploitation",
                    title="Web server segfault detected",
                    description=(
                        "The web server process crashed with a segmentation "
                        "fault. This can indicate memory corruption from "
                        "exploitation attempts."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()[:500]],
                )

            # ---- permission denied ----
            if "permission denied" in low or "access denied" in low:
                perm_counter[str(path)] += 1

    @staticmethod
    def _parse_line(line: str):
        """Try to parse an Apache or Nginx error log line.

        Returns (timestamp, level, message, client) or (None, ...) on failure.
        """
        m = APACHE_ERR_RE.match(line)
        if m:
            try:
                ts = datetime.strptime(
                    m.group("ts").split(".")[0],
                    "%a %b %d %H:%M:%S %Y",
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                ts = None
            return ts, m.group("level"), m.group("msg"), m.group("client")

        m = NGINX_ERR_RE.match(line)
        if m:
            try:
                ts = datetime.strptime(
                    m.group("ts"), "%Y/%m/%d %H:%M:%S"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                ts = None
            return ts, m.group("level"), m.group("msg"), None

        return None, None, line, None
