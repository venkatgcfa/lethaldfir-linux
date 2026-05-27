"""
parsers.web_logs
================

Parses Apache / Nginx access logs in NCSA Combined Log format::

    192.0.2.1 - frank [10/Oct/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0 ..."

Findings raised
---------------
* **HIGH**     Webshell-style requests (POST to ``.php`` / ``.jsp`` etc. in
               an upload-looking path, or ``cmd=``, ``shell=``, ``exec=``)
* **HIGH**     Common scanner / exploit user-agents
               (``sqlmap``, ``nikto``, ``masscan``, ``nuclei``, ``acunetix``)
* **MEDIUM**   Path traversal pattern in URI (``../``, ``%2e%2e``)
* **MEDIUM**   Excessive 4xx volume from a single source (>200 in window)
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import read_lines
from .base import BaseParser


COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+'
    r'(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


SCANNER_AGENTS = (
    "sqlmap", "nikto", "nmap scripting engine", "masscan", "zgrab",
    "acunetix", "nessus", "openvas", "qualys", "wpscan", "dirbuster",
    "gobuster", "ffuf", "feroxbuster", "wfuzz", "fuzzdb", "nuclei",
    "burpsuite", "havij", "metasploit",
)


WEBSHELL_HINTS = (
    "cmd=", "exec=", "shell=", "command=", "?run=", "system(",
    "passthru(", "popen(", "/wso.php", "/c99.php", "/r57.php",
    "/cmd.jsp", "/shell.aspx", "?action=run", "uploadify",
)


TRAVERSAL = ("../", "..%2f", "..%5c", "%2e%2e/", "%2e%2e%2f")


class WebLogsParser(BaseParser):
    name = "web_logs"

    def run(self) -> None:
        files = self.finder.find_by_glob([
            "**/var/log/apache2/access.log*",
            "**/var/log/apache2/*-access.log*",
            "**/var/log/httpd/access_log*",
            "**/var/log/nginx/access.log*",
            "**/var/log/nginx/*-access.log*",
        ])
        seen: set[Path] = set()
        files = [f for f in files if not (f in seen or seen.add(f))]

        # cross-line accumulators
        per_ip_4xx: Counter = Counter()

        for f in files:
            self.note_file(f)
            self._parse_one(f, per_ip_4xx)

        for ip, count in per_ip_4xx.items():
            if count >= 200:
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="reconnaissance",
                    title=f"High 4xx volume from {ip}: {count} responses",
                    description=(
                        f"Source IP {ip} generated {count} 4xx responses in "
                        "web access logs - suggestive of directory brute-force "
                        "or vulnerability scanning."
                    ),
                    artifact="web access logs",
                    metadata={"ip": ip, "count": count},
                )

    def _parse_one(self, path: Path, per_ip_4xx: Counter) -> None:
        for line in read_lines(path):
            m = COMBINED_RE.match(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
            except ValueError:
                continue
            ip = m["ip"]
            req = m["req"]
            status = int(m["status"])
            ua = m["ua"] or ""

            self.emit_event(
                timestamp=ts,
                source="web_access",
                event_type="http_request",
                description=f"{ip} \"{req}\" {status} ua=\"{ua[:60]}\"",
                user=(m["user"] if m["user"] != "-" else None),
                metadata={
                    "ip": ip, "request": req, "status": status,
                    "user_agent": ua, "size": m["size"],
                    "referer": m["referer"] or "",
                },
                raw=line,
            )

            if 400 <= status < 500:
                per_ip_4xx[ip] += 1

            ua_low = ua.lower()
            for sa in SCANNER_AGENTS:
                if sa in ua_low:
                    self.emit_finding(
                        severity=SEV_HIGH,
                        category="reconnaissance",
                        title=f"Scanner user-agent observed: {sa}",
                        description=(
                            f"A request from {ip} carried a User-Agent matching "
                            f"the offensive tool '{sa}'."
                        ),
                        artifact=str(path),
                        timestamp=ts,
                        evidence=[line.strip()],
                        metadata={"ip": ip, "ua": ua},
                    )
                    break

            req_low = req.lower()
            for h in WEBSHELL_HINTS:
                if h in req_low:
                    self.emit_finding(
                        severity=SEV_HIGH,
                        category="execution",
                        title="Possible webshell access",
                        description=(
                            f"HTTP request from {ip} contains tokens commonly "
                            f"associated with webshell command execution: '{h}'."
                        ),
                        artifact=str(path),
                        timestamp=ts,
                        evidence=[line.strip()],
                        metadata={"ip": ip, "request": req},
                    )
                    break
            else:
                for t in TRAVERSAL:
                    if t in req_low:
                        self.emit_finding(
                            severity=SEV_MEDIUM,
                            category="exploitation",
                            title="Path traversal attempt",
                            description=(
                                f"Request from {ip} contains a path-traversal "
                                f"sequence ({t})."
                            ),
                            artifact=str(path),
                            timestamp=ts,
                            evidence=[line.strip()],
                            metadata={"ip": ip, "request": req},
                        )
                        break
