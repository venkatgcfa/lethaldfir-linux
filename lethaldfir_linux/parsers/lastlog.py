"""
parsers.lastlog
===============

Parses ``/var/log/lastlog`` — a sparse, UID-indexed binary file holding
the most recent login per local user.

Linux ``struct lastlog``::

    int32_t ll_time;       /*   4 */
    char    ll_line[32];   /*  32 */
    char    ll_host[256];  /* 256 */

Total: 292 bytes per record. Record at byte offset ``uid * 292``. The
file is sparse — UIDs that have never logged in have ``ll_time == 0``
and the entire 292-byte slot is zero.

To map UID -> username, this parser cooperates with PasswdParser by
reading ``/etc/passwd`` directly (rather than depending on parser
ordering or shared mutable state).

Findings raised
---------------
* **MEDIUM**  Service / system account (UID < 1000, except root) with a
              non-zero last-login timestamp - service accounts should
              not have interactive logins.
* **INFO**    Per-user inventory event for every UID with a recorded
              login.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_MEDIUM, SEV_INFO
from ..core.utils import read_lines
from .base import BaseParser


LASTLOG_FMT  = "<i32s256s"
LASTLOG_SIZE = struct.calcsize(LASTLOG_FMT)
assert LASTLOG_SIZE == 292, f"unexpected lastlog size: {LASTLOG_SIZE}"

# UIDs <= this and not root (0) are treated as service accounts; an
# interactive login is suspicious.
SERVICE_UID_MAX = 999

# UID -> username for built-in service accounts that legitimately *can*
# log in (rare, but seen on some custom distros). Keep this very small.
ALLOWED_INTERACTIVE_SYSTEM_USERS = {"root"}


def _decode_str(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


class LastlogParser(BaseParser):
    name = "lastlog"

    def run(self) -> None:
        # Build UID -> username map from /etc/passwd if available.
        uid_to_user = self._load_uid_map()

        all_records: list[dict] = []
        files = list(self.finder.find_by_suffix(["/var/log/lastlog"]))
        for path in files:
            self.note_file(path)
            records = self._parse_one(path, uid_to_user)
            all_records.extend(records)

        # Write per-parser CSV
        if all_records:
            self.write_csv(
                "lastlog.csv", all_records,
                ["source_file", "uid", "username", "terminal",
                 "remote_host", "last_login", "epoch"],
            )

    # ------------------------------------------------------------------
    def _load_uid_map(self) -> dict[int, str]:
        mapping: dict[int, str] = {}
        for path in self.finder.find_by_suffix(["/etc/passwd"]):
            try:
                for line in read_lines(path):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) < 3:
                        continue
                    try:
                        uid = int(parts[2])
                    except ValueError:
                        continue
                    mapping[uid] = parts[0]
            except OSError:
                continue
        return mapping

    # ------------------------------------------------------------------
    def _parse_one(self, path: Path, uid_to_user: dict[int, str]) -> list[dict]:
        records: list[dict] = []
        try:
            data = path.read_bytes()
        except OSError as exc:
            self.note_error(f"could not read {path}: {exc}")
            return records

        if not data:
            return records

        if len(data) % LASTLOG_SIZE != 0:
            self.note_error(
                f"{path}: size {len(data)} not a multiple of struct size "
                f"{LASTLOG_SIZE}; record alignment may be off"
            )

        max_uid = len(data) // LASTLOG_SIZE
        for uid in range(max_uid):
            chunk = data[uid * LASTLOG_SIZE:(uid + 1) * LASTLOG_SIZE]
            if not chunk or chunk == b"\x00" * LASTLOG_SIZE:
                continue
            try:
                ll_time, line_b, host_b = struct.unpack(LASTLOG_FMT, chunk)
            except struct.error:
                continue
            if ll_time == 0:
                continue

            try:
                ts = datetime.fromtimestamp(ll_time, tz=timezone.utc)
            except (OSError, ValueError, OverflowError):
                continue

            user = uid_to_user.get(uid, f"uid={uid}")
            line = _decode_str(line_b)
            host = _decode_str(host_b)

            records.append({
                "source_file": str(path),
                "uid": uid,
                "username": user,
                "terminal": line,
                "remote_host": host,
                "last_login": ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "epoch": ll_time,
            })

            self.emit_event(
                timestamp=ts,
                source="lastlog",
                event_type="last_login",
                description=(
                    f"lastlog: user={user} (uid={uid}) line={line or '-'} "
                    f"host={host or '-'}"
                ),
                user=user,
                host=host or None,
                metadata={
                    "uid": uid, "line": line, "host": host,
                },
            )

            if (
                uid <= SERVICE_UID_MAX
                and uid != 0
                and user not in ALLOWED_INTERACTIVE_SYSTEM_USERS
            ):
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="account_anomaly",
                    title=f"Service account interactive login: {user}",
                    description=(
                        f"Service / system account '{user}' (uid={uid}) has a "
                        f"recorded interactive login in lastlog. Service "
                        f"accounts should normally never authenticate "
                        f"interactively."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[
                        f"uid={uid} user={user} line={line} host={host} "
                        f"time={ts.isoformat()}"
                    ],
                    metadata={"uid": uid, "line": line, "host": host},
                )

        return records

