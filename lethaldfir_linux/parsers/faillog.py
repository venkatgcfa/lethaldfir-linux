"""
parsers.faillog
===============

Parses binary failed-login accounting and PAM faillock data:

* ``/var/log/faillog``       — UID-indexed binary (``struct faillog``)
* ``/var/run/faillock/*``    — pam_faillock per-user text files (RHEL 8+)

The ``faillog`` file uses fixed-size records indexed by UID (similar to
``lastlog``).  The glibc ``struct faillog`` is::

    struct faillog {
        short  fail_cnt;       /* 2  */
        short  fail_max;       /* 2  */
        char   fail_line[12];  /* 12 */
        time_t fail_time;      /* 4 (32-bit) / 8 (64-bit) */
        long   fail_locktime;  /* 4 (32-bit) / 8 (64-bit) */
    };

With 32-bit ``time_t``/``long`` the record is exactly **24 bytes** (4-byte
aligned, no trailing padding); on a 64-bit host it is 32 bytes. We parse the
24-byte (32-bit) layout; the record stride is derived from the struct so the
two can never disagree.

Findings raised
---------------
* **HIGH**    System / service account (UID < 1000) with recorded failures
* **MEDIUM**  User account with a high failure count (>= 25)
* **INFO**    Each non-zero faillog record emitted as a timeline event
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import read_bytes_safe, read_lines
from .base import BaseParser


# glibc struct faillog:
#   short fail_cnt (2), short fail_max (2), char fail_line[12] (12),
#   time_t fail_time, long fail_locktime
# With 32-bit time_t/long the record is exactly 24 bytes (no padding,
# 4-byte alignment). The stride MUST equal the struct size — a previous
# hard-coded 28 desynced every record after the first, yielding garbage
# UIDs and timestamps.
# Caveat: a faillog written on a 64-bit host uses 8-byte time_t/long
# (32-byte records); that layout is not yet auto-detected here. faillog is
# legacy (pam_faillock superseded it), so the 32-bit layout is the default.
FAILLOG_STRUCT = struct.Struct("<hh12sll")  # 24 bytes
FAILLOG_RECORD_SIZE = FAILLOG_STRUCT.size   # keep stride == struct size


class FaillogParser(BaseParser):
    name = "faillog"

    def run(self) -> None:
        # ---- /var/log/faillog (binary) ----
        for f in self.finder.find_by_suffix(["/var/log/faillog"]):
            self.note_file(f)
            self._parse_faillog_binary(f)

        # ---- /var/run/faillock/* (pam_faillock text, RHEL 8+) ----
        for f in self.finder.find_by_glob([
            "**/var/run/faillock/*",
            "**/run/faillock/*",
        ]):
            if f.is_file():
                self.note_file(f)
                self._parse_faillock(f)

    # ------------------------------------------------------------------
    def _parse_faillog_binary(self, path: Path) -> None:
        data = read_bytes_safe(path)
        if not data:
            return

        record_size = FAILLOG_RECORD_SIZE
        n_records = len(data) // record_size

        for uid in range(n_records):
            offset = uid * record_size
            chunk = data[offset : offset + record_size]
            if len(chunk) < FAILLOG_STRUCT.size:
                continue

            fail_cnt, fail_max, fail_line_raw, fail_time, fail_locktime = \
                FAILLOG_STRUCT.unpack_from(chunk)

            if fail_cnt == 0:
                continue

            fail_line = fail_line_raw.split(b"\x00", 1)[0].decode(
                "ascii", errors="replace"
            ).strip()

            try:
                ts = datetime.fromtimestamp(fail_time, tz=timezone.utc) \
                    if fail_time > 0 else datetime.now(timezone.utc)
            except (OSError, ValueError):
                ts = datetime.now(timezone.utc)

            self.emit_event(
                timestamp=ts,
                source="faillog",
                event_type="faillog_record",
                description=(
                    f"faillog: UID {uid} failures={fail_cnt} "
                    f"max={fail_max} line={fail_line}"
                ),
                metadata={
                    "uid": uid, "fail_cnt": fail_cnt, "fail_max": fail_max,
                    "fail_line": fail_line, "fail_locktime": fail_locktime,
                },
            )

            # --- findings ---
            if uid > 0 and uid < 1000 and fail_cnt > 0:
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="credential_access",
                    title=f"Failed logins for system account UID {uid}",
                    description=(
                        f"faillog records {fail_cnt} failed login attempt(s) "
                        f"for UID {uid} (a system/service account). "
                        "Service accounts should not have interactive login "
                        "failures unless under attack."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    metadata={"uid": uid, "fail_cnt": fail_cnt},
                )
            elif fail_cnt >= 25:
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="credential_access",
                    title=f"High failure count for UID {uid}: {fail_cnt}",
                    description=(
                        f"faillog records {fail_cnt} cumulative failed login "
                        f"attempts for UID {uid}."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    metadata={"uid": uid, "fail_cnt": fail_cnt},
                )

    # ------------------------------------------------------------------
    def _parse_faillock(self, path: Path) -> None:
        """Parse pam_faillock per-user text files.

        Format (one line per failure)::
            When    Type Source    Valid
            2024-09-01 12:34:56   RHOST 192.0.2.1   V
        """
        user = path.name
        count = 0
        last_ts = None
        for line in read_lines(path):
            line = line.strip()
            if not line or line.startswith("When"):
                continue
            count += 1
            # Try to extract timestamp from the start of the line
            parts = line.split()
            if len(parts) >= 2:
                try:
                    ts = datetime.strptime(
                        f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                    last_ts = ts
                except ValueError:
                    pass

        if count > 0:
            ts = last_ts or datetime.now(timezone.utc)
            self.emit_event(
                timestamp=ts,
                source="faillock",
                event_type="faillock_record",
                description=(
                    f"pam_faillock: user={user} failures={count}"
                ),
                user=user,
                metadata={"user": user, "count": count},
            )
            if count >= 10:
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="credential_access",
                    title=f"pam_faillock: {count} failures for {user}",
                    description=(
                        f"pam_faillock records {count} failed authentication "
                        f"attempts for user '{user}'."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    metadata={"user": user, "count": count},
                )
