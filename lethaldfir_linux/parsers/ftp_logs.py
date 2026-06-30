"""
parsers.ftp_logs
================

Parses FTP server logs:

* ``/var/log/vsftpd.log``              (vsftpd)
* ``/var/log/xferlog``                 (standard xferlog format)
* ``/var/log/proftpd/proftpd.log``     (ProFTPD)
* ``/var/log/pure-ftpd/transfer.log``  (Pure-FTPd)

Findings raised
---------------
* **HIGH**     Upload of suspicious file types (.php, .jsp, .war, .sh, .elf)
* **HIGH**     Anonymous login detected
* **MEDIUM**   FTP brute-force pattern (>= 20 failures from one IP)
* **INFO**     Each transfer / login event emitted as a timeline event
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import parse_syslog_timestamp, read_lines
from .base import BaseParser


# Standard xferlog format (used by vsftpd, wu-ftpd):
# DDD Mon DD HH:MM:SS YYYY T duration remote-host file-size filename
#   transfer-type special-action-flag direction access-mode username
#   service-name auth-method auth-user-id completion-status
XFERLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+"
    r"(?P<duration>\d+)\s+(?P<host>\S+)\s+(?P<size>\d+)\s+(?P<file>\S+)\s+"
    r"(?P<type>[ab])\s+(?P<special>[_CUT])\s+(?P<dir>[dio])\s+"
    r"(?P<access>[agr])\s+(?P<user>\S+)\s+(?P<service>\S+)\s+"
    r"(?P<auth>\d)\s+(?P<authuser>\S*)\s+(?P<status>[ci])"
)

# vsftpd syslog-style log entries
VSFTPD_LOGIN_RE = re.compile(
    r"vsftpd.*?(?:OK|FAIL)\s+LOGIN:\s+Client\s+\"(?P<ip>[^\"]+)\""
    r"(?:,\s+anon\s+password\s+\"[^\"]*\")?"
    r"(?:,\s+user\s+\"(?P<user>[^\"]*)\")?"
)
VSFTPD_CONNECT_RE = re.compile(
    r"vsftpd.*?CONNECT:\s+Client\s+\"(?P<ip>[^\"]+)\""
)
VSFTPD_UPLOAD_RE = re.compile(
    r"vsftpd.*?OK\s+UPLOAD:\s+Client\s+\"(?P<ip>[^\"]+)\",\s+\"(?P<file>[^\"]+)\""
)
VSFTPD_DOWNLOAD_RE = re.compile(
    r"vsftpd.*?OK\s+DOWNLOAD:\s+Client\s+\"(?P<ip>[^\"]+)\",\s+\"(?P<file>[^\"]+)\""
)
VSFTPD_FAIL_RE = re.compile(
    r"vsftpd.*?FAIL\s+LOGIN:\s+Client\s+\"(?P<ip>[^\"]+)\""
)

SUSPICIOUS_EXTENSIONS = (
    ".php", ".jsp", ".jspx", ".war", ".sh", ".elf", ".py",
    ".pl", ".cgi", ".asp", ".aspx", ".phtml",
)


class FtpLogsParser(BaseParser):
    name = "ftp_logs"

    def run(self) -> None:
        fail_counter: Counter = Counter()

        # xferlog
        for f in self.finder.find_log_family("xferlog"):
            self.note_file(f)
            self._parse_xferlog(f)

        # vsftpd.log
        for f in self.finder.find_log_family("vsftpd.log"):
            self.note_file(f)
            self._parse_vsftpd(f, fail_counter)

        # proftpd
        for f in self.finder.find_by_glob([
            "**/var/log/proftpd/*.log*",
            "**/var/log/proftpd/proftpd.log*",
        ]):
            self.note_file(f)
            self._parse_proftpd(f, fail_counter)

        # pure-ftpd
        for f in self.finder.find_by_glob([
            "**/var/log/pure-ftpd/*.log*",
        ]):
            self.note_file(f)
            self._parse_generic_syslog_ftp(f, fail_counter)

        # Post-pass: brute-force
        for ip, count in fail_counter.items():
            if count >= 20:
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="credential_access",
                    title=f"FTP brute-force from {ip}: {count} failures",
                    description=(
                        f"FTP logs record {count} failed login attempts "
                        f"from {ip}."
                    ),
                    artifact="ftp logs",
                    metadata={"ip": ip, "count": count},
                )

    # ------------------------------------------------------------------
    def _parse_xferlog(self, path: Path) -> None:
        for line in read_lines(path):
            m = XFERLOG_RE.match(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(m["ts"], "%a %b %d %H:%M:%S %Y") \
                    .replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            direction = "upload" if m["dir"] == "i" else "download"
            user = m["user"]
            filename = m["file"]
            host = m["host"]

            self.emit_event(
                timestamp=ts,
                source="xferlog",
                event_type=f"ftp_{direction}",
                description=(
                    f"FTP {direction}: {user}@{host} file={filename} "
                    f"size={m['size']}"
                ),
                user=user,
                host=host,
                metadata={
                    "file": filename, "size": int(m["size"]),
                    "host": host, "direction": direction,
                },
                raw=line,
            )

            # Check for anonymous
            if user in ("ftp", "anonymous"):
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="credential_access",
                    title=f"Anonymous FTP {direction} from {host}",
                    description=(
                        f"Anonymous FTP access detected from {host}. "
                        f"File: {filename}"
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()],
                )

            # Check for suspicious uploads
            if direction == "upload":
                low = filename.lower()
                for ext in SUSPICIOUS_EXTENSIONS:
                    if low.endswith(ext):
                        self.emit_finding(
                            severity=SEV_HIGH,
                            category="execution",
                            title=f"Suspicious FTP upload: {filename}",
                            description=(
                                f"A file with extension '{ext}' was uploaded "
                                f"via FTP by {user} from {host}. This may "
                                "indicate webshell deployment."
                            ),
                            artifact=str(path),
                            timestamp=ts,
                            evidence=[line.strip()],
                        )
                        break

    def _parse_vsftpd(self, path: Path, fail_counter: Counter) -> None:
        for line in read_lines(path):
            ts = parse_syslog_timestamp(line)
            if ts is None:
                continue

            m = VSFTPD_FAIL_RE.search(line)
            if m:
                ip = m.group("ip")
                fail_counter[ip] += 1
                self.emit_event(
                    timestamp=ts,
                    source="vsftpd",
                    event_type="ftp_login_failed",
                    description=f"FTP login failed from {ip}",
                    metadata={"ip": ip},
                    raw=line,
                )
                continue

            m = VSFTPD_UPLOAD_RE.search(line)
            if m:
                ip = m.group("ip")
                filename = m.group("file")
                self.emit_event(
                    timestamp=ts,
                    source="vsftpd",
                    event_type="ftp_upload",
                    description=f"FTP upload from {ip}: {filename}",
                    metadata={"ip": ip, "file": filename},
                    raw=line,
                )
                low = filename.lower()
                for ext in SUSPICIOUS_EXTENSIONS:
                    if low.endswith(ext):
                        self.emit_finding(
                            severity=SEV_HIGH,
                            category="execution",
                            title=f"Suspicious FTP upload: {filename}",
                            description=(
                                f"A file with extension '{ext}' was uploaded "
                                f"via vsftpd from {ip}."
                            ),
                            artifact=str(path),
                            timestamp=ts,
                            evidence=[line.strip()],
                        )
                        break
                continue

            m = VSFTPD_DOWNLOAD_RE.search(line)
            if m:
                self.emit_event(
                    timestamp=ts,
                    source="vsftpd",
                    event_type="ftp_download",
                    description=f"FTP download from {m['ip']}: {m['file']}",
                    metadata={"ip": m["ip"], "file": m["file"]},
                    raw=line,
                )

    def _parse_proftpd(self, path: Path, fail_counter: Counter) -> None:
        """ProFTPD uses syslog-style format."""
        self._parse_generic_syslog_ftp(path, fail_counter)

    def _parse_generic_syslog_ftp(self, path: Path,
                                   fail_counter: Counter) -> None:
        for line in read_lines(path):
            ts = parse_syslog_timestamp(line)
            if ts is None:
                continue
            low = line.lower()

            if "login failed" in low or "authentication failed" in low:
                # Try to extract IP
                ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                ip = ip_m.group(1) if ip_m else "unknown"
                fail_counter[ip] += 1
                self.emit_event(
                    timestamp=ts,
                    source="ftp_log",
                    event_type="ftp_login_failed",
                    description=f"FTP login failed: {line.strip()[:200]}",
                    metadata={"ip": ip},
                    raw=line,
                )
            elif "upload" in low or "stor " in low:
                self.emit_event(
                    timestamp=ts,
                    source="ftp_log",
                    event_type="ftp_upload",
                    description=f"FTP upload: {line.strip()[:200]}",
                    raw=line,
                )
            else:
                self.emit_event(
                    timestamp=ts,
                    source="ftp_log",
                    event_type="ftp_event",
                    description=line.strip()[:300],
                    raw=line,
                )
