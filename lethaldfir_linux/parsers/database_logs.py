"""
parsers.database_logs
=====================

Parses MySQL/MariaDB/PostgreSQL server logs for auth failures,
dangerous SQL patterns, and user management events.

Files: /var/log/mysql/*, /var/log/mariadb/*, /var/log/postgresql/*

Findings: HIGH for INTO OUTFILE/LOAD_FILE/UDF, MEDIUM for auth failures
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import parse_syslog_timestamp, read_lines
from .base import BaseParser

MYSQL_TS_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
PG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<tz>\S+)\s+\[(?P<pid>\d+)\]\s+"
    r"(?:(?P<user>\S+)@(?P<db>\S+)\s+)?(?P<level>\S+):\s+(?P<msg>.*)"
)
SQL_DANGEROUS = (
    "into outfile", "into dumpfile", "load_file(", "load data infile",
    "create function", "soname",
)
SQL_USER_MGMT = re.compile(
    r"(?:CREATE\s+USER|GRANT\s+ALL|ALTER\s+USER|DROP\s+USER)", re.IGNORECASE,
)
AUTH_FAIL = ("access denied", "authentication failed",
             "password authentication failed", "no pg_hba.conf entry")


class DatabaseLogsParser(BaseParser):
    name = "database_logs"

    def run(self) -> None:
        fail_ctr: Counter = Counter()
        for f in self.finder.find_by_glob([
            "**/var/log/mysql/*.log*", "**/var/log/mariadb/*.log*",
        ]):
            self.note_file(f); self._parse_mysql(f, fail_ctr)
        for f in self.finder.find_by_glob([
            "**/var/log/postgresql/*.log*", "**/var/log/postgresql/postgresql-*",
        ]):
            self.note_file(f); self._parse_postgres(f, fail_ctr)
        for src, n in fail_ctr.items():
            if n >= 15:
                self.emit_finding(severity=SEV_MEDIUM, category="credential_access",
                    title=f"Database auth failures: {n}", artifact=src,
                    description=f"{n} auth failures in {src}.", metadata={"count": n})

    def _parse_mysql(self, path: Path, fc: Counter) -> None:
        for line in read_lines(path):
            m = MYSQL_TS_RE.match(line)
            if not m: continue
            try:
                raw = m["ts"].replace("Z", "+00:00")
                ts = datetime.fromisoformat(raw) if "T" in raw else \
                    datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
            except ValueError: continue
            msg = line[m.end():].strip(); low = msg.lower()
            self.emit_event(timestamp=ts, source="mysql", event_type="database_event",
                description=msg[:300], raw=line)
            if any(p in low for p in AUTH_FAIL): fc[str(path)] += 1
            for pat in SQL_DANGEROUS:
                if pat in low:
                    self.emit_finding(severity=SEV_HIGH, category="execution",
                        title=f"Dangerous SQL: {pat}", artifact=str(path), timestamp=ts,
                        description=f"Database log contains '{pat}'.",
                        evidence=[line.strip()[:500]]); break
            if SQL_USER_MGMT.search(msg):
                self.emit_finding(severity=SEV_MEDIUM, category="account_management",
                    title="Database user management event", artifact=str(path),
                    timestamp=ts, description="CREATE/GRANT/ALTER/DROP USER logged.",
                    evidence=[line.strip()[:500]])

    def _parse_postgres(self, path: Path, fc: Counter) -> None:
        for line in read_lines(path):
            m = PG_RE.match(line)
            if m:
                try:
                    ts = datetime.strptime(m["ts"].split(".")[0],
                        "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                except ValueError: continue
                msg = m["msg"]; user = m["user"]
            else:
                ts = parse_syslog_timestamp(line)
                if ts is None: continue
                msg = line; user = None
            self.emit_event(timestamp=ts, source="postgresql",
                event_type="database_event", description=(msg or line)[:300],
                user=user, raw=line)
            low = (msg or line).lower()
            if any(p in low for p in AUTH_FAIL): fc[str(path)] += 1
            for pat in SQL_DANGEROUS:
                if pat in low:
                    self.emit_finding(severity=SEV_HIGH, category="execution",
                        title=f"Dangerous SQL in PostgreSQL: {pat}",
                        artifact=str(path), timestamp=ts,
                        description=f"PostgreSQL log contains '{pat}'.",
                        evidence=[line.strip()[:500]]); break
