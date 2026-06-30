"""
parsers.wtmp
============

Parses binary login accounting files using both external Linux commands
(``utmpdump``, ``last``, ``lastb``) and a pure-Python struct fallback.

Files covered
-------------
* ``/var/log/wtmp``     — successful logins / logouts / boots / shutdowns
* ``/var/log/btmp``     — failed logins
* ``/var/run/utmp``     — currently logged-in (snapshot at collection time)

Dual-mode strategy
------------------
1. **When available** (Linux/WSL): uses ``utmpdump`` for raw record dumps,
   ``last``/``lastb`` for session-level parsing with login/logout times,
   and duration. This matches the LethalDFIR standalone binary login parser.
2. **Fallback** (macOS, no util-linux): pure-Python struct parsing using
   the 384-byte glibc ``struct utmp`` layout.

Per-parser CSV output
---------------------
* ``csv/utmpdump_wtmp.csv``       — raw utmpdump records from wtmp
* ``csv/utmpdump_btmp.csv``       — raw utmpdump records from btmp
* ``csv/last_wtmp.csv``           — session-level records from ``last``
* ``csv/lastb_btmp.csv``          — failed login records from ``lastb``
* ``csv/unified_login_timeline.csv`` — merged chronological login timeline

Findings raised
---------------
* **CRITICAL** IPs in both btmp AND wtmp (brute-force → success)
* **HIGH**     High volume of failed logins (≥50 btmp records)
* **MEDIUM**   File size not a multiple of 384 bytes (possible tampering)
* **MEDIUM**   EMPTY records (type 0) in wtmp — possible zeroed entries
* **MEDIUM**   Orphaned DEAD_PROCESS records — login may have been deleted
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import struct
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM
from .base import BaseParser


# ============================================================================
# CONSTANTS
# ============================================================================

UTMP_FMT = "<h2xi32s4s32s256shhiii16s20s"
UTMP_SIZE = struct.calcsize(UTMP_FMT)
assert UTMP_SIZE == 384

TYPE_NAMES = {
    0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
    5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS",
    8: "DEAD_PROCESS", 9: "ACCOUNTING",
}

UTMPDUMP_RE = re.compile(
    r'\[(\d+)\]\s+'       # ut_type
    r'\[(\d+)\]\s+'       # ut_pid
    r'\[([^\]]*)\]\s+'    # ut_id
    r'\[([^\]]*)\]\s+'    # ut_user
    r'\[([^\]]*)\]\s+'    # ut_line
    r'\[([^\]]*)\]\s+'    # ut_host
    r'\[([^\]]*)\]\s+'    # ut_addr
    r'\[([^\]]*)\]'       # timestamp
)

UTMPDUMP_FIELDS = [
    "source_file", "record_type_id", "record_type", "pid",
    "terminal_id", "username", "terminal", "remote_host",
    "remote_ip", "timestamp", "timestamp_epoch",
]

LAST_FIELDS = [
    "source_file", "event_type", "username", "terminal",
    "remote_ip", "login_time", "logout_time", "duration",
    "session_status",
]

TIMELINE_FIELDS = [
    "timestamp", "source", "source_file", "event_type",
    "username", "terminal", "remote_ip", "logout_time",
    "duration", "session_status",
]


def _decode_str(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _decode_addr(addr: bytes) -> str:
    """Decode a utmp ut_addr_v6 field (4x int32, network order) to an IP.

    IPv4 addresses occupy the first 4 bytes with the rest zero; IPv6 uses
    all 16. Returns "" for empty/unspecified addresses. Without this, the
    pure-Python (no util-linux) path produced no source IPs, so btmp
    brute-force IP correlation was impossible on those hosts.
    """
    if not addr or len(addr) < 4:
        return ""
    try:
        if addr[4:16] == b"\x00" * 12:
            ip = socket.inet_ntop(socket.AF_INET, addr[:4])
        else:
            ip = socket.inet_ntop(socket.AF_INET6, addr[:16])
    except (OSError, ValueError):
        return ""
    return "" if ip in ("0.0.0.0", "::") else ip


def _has_tool(name: str) -> bool:
    return shutil.which(name) is not None


class WtmpParser(BaseParser):
    name = "wtmp_btmp"

    def run(self) -> None:
        has_utmpdump = _has_tool("utmpdump")
        has_last = _has_tool("last")
        has_lastb = _has_tool("lastb")

        # Collect all binary log files
        wtmp_files = list(self.finder.find_log_family("wtmp"))
        btmp_files = list(self.finder.find_log_family("btmp"))
        utmp_files = []
        for suffix in ("/var/run/utmp", "/run/utmp", "/var/log/utmp"):
            utmp_files.extend(self.finder.find_by_suffix([suffix]))

        all_files = {
            "wtmp": wtmp_files,
            "btmp": btmp_files,
            "utmp": utmp_files,
        }

        # Note all files
        for files in all_files.values():
            for f in files:
                self.note_file(f)

        # ---- Validate file integrity ----
        validation_data = []
        for ftype, files in all_files.items():
            for fpath in files:
                vd = self._validate_file(fpath, ftype)
                validation_data.append(vd)

        self.case.set_artifact("login_file_validation", validation_data)

        # ---- Parse with utmpdump (raw records) ----
        utmpdump_records: dict[str, list[dict]] = {}
        all_utmpdump: list[dict] = []

        for ftype, files in all_files.items():
            for fpath in files:
                if has_utmpdump:
                    records = self._parse_utmpdump(fpath)
                else:
                    records = self._parse_struct(fpath)

                key = f"{ftype}_{fpath.name}"
                utmpdump_records[key] = records
                all_utmpdump.extend(records)

                # Emit timeline events from raw records
                for rec in records:
                    ts = self._parse_ts(rec.get("timestamp", ""))
                    if ts is None:
                        continue

                    ut_type = rec.get("record_type_id", 0)
                    is_failed = "btmp" in ftype
                    event_type = "login_failed" if is_failed else {
                        2: "system_boot", 7: "session_open",
                        8: "session_close", 1: "runlevel_change",
                    }.get(ut_type, "utmp_record")

                    self.emit_event(
                        timestamp=ts,
                        source=ftype,
                        event_type=event_type,
                        description=(
                            f"{ftype}: type={rec.get('record_type', '')} "
                            f"user={rec.get('username', '-')} "
                            f"line={rec.get('terminal', '-')} "
                            f"host={rec.get('remote_host', '-')}"
                        ),
                        user=rec.get("username") or None,
                        host=rec.get("remote_host") or None,
                        metadata={
                            "type": rec.get("record_type", ""),
                            "pid": rec.get("pid", 0),
                            "line": rec.get("terminal", ""),
                        },
                    )

                # Write per-file CSV
                csv_name = f"utmpdump_{ftype}_{fpath.name}.csv"
                self.write_csv(csv_name, records, UTMPDUMP_FIELDS)

        # ---- Parse with last/lastb (session records) ----
        all_last: list[dict] = []
        btmp_last: list[dict] = []

        if has_last:
            for fpath in wtmp_files:
                records = self._parse_last(fpath, is_btmp=False)
                all_last.extend(records)
                self.write_csv(
                    f"last_{fpath.name}.csv", records, LAST_FIELDS
                )

        if has_lastb:
            for fpath in btmp_files:
                records = self._parse_last(fpath, is_btmp=True)
                btmp_last.extend(records)
                all_last.extend(records)
                self.write_csv(
                    f"lastb_{fpath.name}.csv", records, LAST_FIELDS
                )

        # ---- Build unified login timeline ----
        timeline = self._build_timeline(all_last)
        self.write_csv("unified_login_timeline.csv", timeline, TIMELINE_FIELDS)

        # ---- Tamper detection findings ----
        self._check_tampering(utmpdump_records, validation_data)

        # ---- Brute-force analysis ----
        if btmp_last:
            bf_data = self._bruteforce_analysis(btmp_last, all_last)
            self.case.set_artifact("bruteforce_analysis", bf_data)

        # ---- High-volume btmp finding ----
        btmp_events = [
            e for e in self.case.events if e.source == "btmp"
        ]
        if len(btmp_events) >= 50:
            self.emit_finding(
                severity=SEV_HIGH,
                category="credential_access",
                title=f"High volume of failed logins (btmp): {len(btmp_events)}",
                description=(
                    f"{len(btmp_events)} failed login records were found in "
                    "btmp, suggesting password-spray or brute-force activity."
                ),
                artifact="btmp",
                metadata={"count": len(btmp_events)},
            )

    # ==================================================================
    # VALIDATION
    # ==================================================================
    def _validate_file(self, fpath: Path, ftype: str) -> dict:
        try:
            size = fpath.stat().st_size
        except OSError:
            size = 0
        record_count = size // UTMP_SIZE
        remainder = size % UTMP_SIZE
        integrity = "PASS" if remainder == 0 else "FAIL - POSSIBLE TAMPERING"

        if remainder != 0:
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="log_tampering",
                title=f"Binary log size anomaly: {fpath.name}",
                description=(
                    f"{fpath} is {size} bytes with {remainder} bytes remainder "
                    f"(not a multiple of 384). This may indicate truncation "
                    "or tampering."
                ),
                artifact=str(fpath),
                metadata={"size": size, "remainder": remainder},
            )

        return {
            "path": str(fpath), "type": ftype, "size_bytes": size,
            "record_count": record_count, "remainder": remainder,
            "integrity": integrity,
        }

    # ==================================================================
    # UTMPDUMP PARSING (external command)
    # ==================================================================
    def _parse_utmpdump(self, fpath: Path) -> list[dict]:
        records = []
        try:
            result = subprocess.run(
                ["utmpdump", str(fpath)],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                self.note_error(
                    f"utmpdump error on {fpath}: {result.stderr.strip()}"
                )
                return self._parse_struct(fpath)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return self._parse_struct(fpath)

        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            m = UTMPDUMP_RE.match(line)
            if not m:
                continue

            ut_type = int(m.group(1))
            ts_raw = m.group(8).strip()
            ts_parsed, ts_epoch = self._parse_utmpdump_ts(ts_raw)

            records.append({
                "source_file": str(fpath),
                "record_type_id": ut_type,
                "record_type": TYPE_NAMES.get(ut_type, f"UNKNOWN({ut_type})"),
                "pid": int(m.group(2)),
                "terminal_id": m.group(3).strip(),
                "username": m.group(4).strip(),
                "terminal": m.group(5).strip(),
                "remote_host": m.group(6).strip(),
                "remote_ip": m.group(7).strip(),
                "timestamp": ts_parsed,
                "timestamp_epoch": ts_epoch,
            })

        return records

    @staticmethod
    def _parse_utmpdump_ts(ts_raw: str):
        ts_clean = ts_raw.replace(",", ".")
        for fmt in ["%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"]:
            try:
                dt = datetime.strptime(ts_clean, fmt)
                return (
                    dt.strftime("%Y-%m-%d %H:%M:%S %Z").strip(),
                    int(dt.timestamp()),
                )
            except ValueError:
                continue
        return ts_raw, 0

    # ==================================================================
    # STRUCT PARSING (pure-Python fallback)
    # ==================================================================
    def _parse_struct(self, fpath: Path) -> list[dict]:
        records = []
        try:
            data = fpath.read_bytes()
        except OSError:
            return records

        offset = 0
        while offset + UTMP_SIZE <= len(data):
            chunk = data[offset:offset + UTMP_SIZE]
            offset += UTMP_SIZE
            try:
                rec = struct.unpack(UTMP_FMT, chunk)
            except struct.error:
                continue

            (ut_type, ut_pid, line_b, id_b, user_b, host_b,
             e_term, e_exit, session, tv_sec, tv_usec, _addr, _) = rec

            if ut_type == 0 and not any(
                [line_b.strip(b"\x00"), user_b.strip(b"\x00")]
            ):
                continue

            try:
                ts = datetime.fromtimestamp(tv_sec, tz=timezone.utc)
            except (OSError, ValueError, OverflowError):
                continue

            records.append({
                "source_file": str(fpath),
                "record_type_id": ut_type,
                "record_type": TYPE_NAMES.get(ut_type, f"TYPE{ut_type}"),
                "pid": ut_pid,
                "terminal_id": _decode_str(id_b),
                "username": _decode_str(user_b),
                "terminal": _decode_str(line_b),
                "remote_host": _decode_str(host_b),
                "remote_ip": _decode_addr(_addr),
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "timestamp_epoch": tv_sec,
            })

        return records

    # ==================================================================
    # LAST / LASTB PARSING (external command)
    # ==================================================================
    def _parse_last(self, fpath: Path, is_btmp: bool) -> list[dict]:
        cmd = "lastb" if is_btmp else "last"
        records = []

        try:
            result = subprocess.run(
                [cmd, "-f", str(fpath), "-i", "--time-format=iso", "-w"],
                capture_output=True, text=True, timeout=60,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return records

        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("wtmp begins") or \
               line.startswith("btmp begins"):
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            username = parts[0]
            terminal = parts[1]

            # Extract IP
            remote_ip = ""
            for part in parts:
                if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", part):
                    remote_ip = part
                    break

            # Extract ISO timestamps
            timestamps = [
                p for p in parts if re.match(r"\d{4}-\d{2}-\d{2}T", p)
            ]
            login_time = timestamps[0] if timestamps else ""
            logout_time = timestamps[1] if len(timestamps) > 1 else ""

            # Session status
            session_status = ""
            if "still logged in" in line:
                session_status = "still logged in"
            elif "still running" in line:
                session_status = "still running"
            elif "crash" in line:
                session_status = "crash"

            # Duration
            dur_match = re.search(r"\(([^)]+)\)", line)
            duration = dur_match.group(1) if dur_match else ""

            # Event type
            event_type = "FAILED_LOGIN" if is_btmp else "LOGIN_SESSION"
            if username == "reboot":
                event_type = "REBOOT"
            elif username == "shutdown":
                event_type = "SHUTDOWN"
            elif username == "runlevel":
                event_type = "RUNLEVEL_CHANGE"

            records.append({
                "source_file": str(fpath),
                "event_type": event_type,
                "username": username,
                "terminal": terminal,
                "remote_ip": remote_ip,
                "login_time": login_time,
                "logout_time": logout_time,
                "duration": duration,
                "session_status": session_status,
            })

        return records

    # ==================================================================
    # UNIFIED TIMELINE
    # ==================================================================
    @staticmethod
    def _build_timeline(all_last: list[dict]) -> list[dict]:
        timeline = []
        for rec in all_last:
            source = "btmp" if rec.get("event_type") == "FAILED_LOGIN" \
                else "wtmp"
            timeline.append({
                "timestamp": rec.get("login_time", ""),
                "source": source,
                "source_file": os.path.basename(
                    rec.get("source_file", "")),
                "event_type": rec.get("event_type", ""),
                "username": rec.get("username", ""),
                "terminal": rec.get("terminal", ""),
                "remote_ip": rec.get("remote_ip", ""),
                "logout_time": rec.get("logout_time", ""),
                "duration": rec.get("duration", ""),
                "session_status": rec.get("session_status", ""),
            })

        timeline.sort(key=lambda r: r.get("timestamp") or "9999")
        return timeline

    # ==================================================================
    # TAMPER DETECTION
    # ==================================================================
    def _check_tampering(
        self,
        utmpdump_records: dict[str, list[dict]],
        validation_data: list[dict],
    ) -> None:
        for file_key, records in utmpdump_records.items():
            if "btmp" in file_key.lower():
                continue

            # EMPTY record check
            empty = [r for r in records if r.get("record_type_id") == 0]
            if empty:
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="log_tampering",
                    title=f"EMPTY records in {file_key}: {len(empty)}",
                    description=(
                        f"{len(empty)} EMPTY (type 0) records found in "
                        f"{file_key}. These may indicate zeroed-out login "
                        "entries — a common log tampering technique."
                    ),
                    artifact=file_key,
                    metadata={"count": len(empty)},
                )

            # Orphaned DEAD_PROCESS check
            user_pids = {
                r["pid"] for r in records if r.get("record_type_id") == 7
            }
            dead_pids = {
                r["pid"] for r in records if r.get("record_type_id") == 8
            }
            orphaned = dead_pids - user_pids - {0}
            if orphaned:
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="log_tampering",
                    title=f"Orphaned DEAD_PROCESS in {file_key}",
                    description=(
                        f"{len(orphaned)} DEAD_PROCESS records have no "
                        "matching USER_PROCESS — the login entry may have "
                        "been deleted. Orphaned PIDs: "
                        f"{sorted(orphaned)[:10]}"
                    ),
                    artifact=file_key,
                    metadata={"orphaned_pids": sorted(orphaned)[:20]},
                )

    # ==================================================================
    # BRUTE-FORCE ANALYSIS
    # ==================================================================
    def _bruteforce_analysis(
        self,
        btmp_records: list[dict],
        all_last: list[dict],
    ) -> dict:
        ip_counter: Counter = Counter()
        user_counter: Counter = Counter()
        hourly: Counter = Counter()

        for rec in btmp_records:
            ip = rec.get("remote_ip", "").strip()
            user = rec.get("username", "").strip()
            ts = rec.get("login_time", "")
            if ip:
                ip_counter[ip] += 1
            if user:
                user_counter[user] += 1
            if ts and "T" in ts:
                try:
                    hourly[ts.split("T")[1][:2]] += 1
                except (IndexError, ValueError):
                    pass

        # Cross-reference: IPs in both btmp and wtmp
        wtmp_ips = {
            r["remote_ip"] for r in all_last
            if r.get("event_type") == "LOGIN_SESSION"
            and r.get("remote_ip", "").strip()
        }
        btmp_ips = {
            r["remote_ip"] for r in btmp_records
            if r.get("remote_ip", "").strip()
        }
        compromised = wtmp_ips & btmp_ips

        # Emit critical findings for compromised IPs
        for ip in compromised:
            bf_count = sum(
                1 for r in btmp_records if r.get("remote_ip") == ip
            )
            self.emit_finding(
                severity=SEV_CRITICAL,
                category="credential_access",
                title=f"Brute-force SUCCESS: {ip}",
                description=(
                    f"IP {ip} appears in BOTH btmp ({bf_count} failed "
                    "attempts) AND wtmp (successful login). This strongly "
                    "indicates a compromised account via brute-force."
                ),
                artifact="btmp + wtmp cross-reference",
                metadata={"ip": ip, "failed_count": bf_count},
            )

        bf_data = {
            "total_attempts": len(btmp_records),
            "top_ips": ip_counter.most_common(25),
            "top_users": user_counter.most_common(25),
            "hourly_distribution": dict(sorted(hourly.items())),
            "compromised_ips": sorted(compromised),
        }

        # Write brute-force CSV
        bf_csv = []
        for ip, count in ip_counter.most_common(100):
            bf_csv.append({
                "ip": ip, "attempts": count,
                "successful_login": "YES" if ip in compromised else "NO",
            })
        self.write_csv(
            "bruteforce_top_ips.csv", bf_csv,
            ["ip", "attempts", "successful_login"],
        )

        user_csv = [
            {"username": u, "attempts": c}
            for u, c in user_counter.most_common(100)
        ]
        self.write_csv(
            "bruteforce_top_users.csv", user_csv,
            ["username", "attempts"],
        )

        return bf_data

    # ==================================================================
    # HELPERS
    # ==================================================================
    @staticmethod
    def _parse_ts(ts_str: str) -> datetime | None:
        if not ts_str:
            return None
        # Try ISO format first
        if "T" in ts_str:
            try:
                return datetime.fromisoformat(
                    ts_str.replace("Z", "+00:00")
                )
            except ValueError:
                pass
        # Try "YYYY-MM-DD HH:MM:SS UTC"
        for fmt in ["%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S"]:
            try:
                dt = datetime.strptime(ts_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        return None
