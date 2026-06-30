"""
parsers.syslog
==============

Parses the general syslog family. Each file is processed line-by-line;
every line becomes a TimelineEvent with the originating filename as the
``source`` and the syslog program (between ``HOST`` and ``:``) as the
``event_type``.

Files covered (suffix-matched, with rotated/.gz variants picked up
automatically by ``finder.find_log_family``):

* ``/var/log/messages``   — RHEL/CentOS general syslog
* ``/var/log/syslog``     — Debian/Ubuntu general syslog
* ``/var/log/kern.log``   — kernel ring buffer copy
* ``/var/log/dmesg``      — boot-time kernel ring buffer
* ``/var/log/boot.log``   — init / systemd boot output
* ``/var/log/cron``       — RHEL cron log
* ``/var/log/cron.log``   — Debian cron log (variant)
* ``/var/log/maillog``    — RHEL mail log
* ``/var/log/mail.log``   — Debian mail log
* ``/var/log/mail.err``   — Debian mail errors
* ``/var/log/daemon.log`` — Debian daemon-only feed
* ``/var/log/user.log``   — user-facility feed (Debian)
* ``/var/log/debug``      — debug-facility feed

Findings raised
---------------
* **HIGH**    line containing suspicious tokens (curl|bash, nc -e, base64
              -d, /dev/tcp/, memfd_create, /tmp/., …)
* **HIGH**    OOM-killer activity in kern.log / messages
* **HIGH**    USB mass-storage attach event in kern.log / messages
* **HIGH**    SELinux/AppArmor denial in kern.log / messages
* **MEDIUM**  segfault / general protection fault clusters
* **INFO**    every other parsed line emits a timeline event only
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import (
    SUSPICIOUS_TOKENS,
    find_suspicious_tokens,
    parse_syslog_timestamp,
    read_lines,
)
from .base import BaseParser


# After the timestamp, the message body looks like:
#   <hostname> <program>[<pid>]: <text>
# ...or, on Debian, sometimes:
#   <hostname> <program>: <text>
SYSLOG_BODY_RE = re.compile(
    r"^\s*(?P<host>\S+)\s+"
    r"(?P<prog>[^\s\[:]+)"
    r"(?:\[(?P<pid>\d+)\])?"
    r":\s*(?P<msg>.*)$"
)

# kernel-style line in kern.log starts with "kernel:" after the host;
# dmesg-style starts with "[ 12.345678] <text>".
DMESG_RE = re.compile(r"^\[\s*(?P<rel>\d+\.\d+)\]\s+(?P<msg>.*)$")

OOM_TOKENS    = ("out of memory", "oom-killer", "killed process")
USB_TOKENS    = ("usb-storage", "new usb device found", "usb mass storage")
SELINUX_TOKENS = ("avc:", "denied  {", "selinux is preventing")
APPARMOR_TOKENS = ("apparmor=\"denied\"", "apparmor: denied")
CRASH_TOKENS  = ("segfault", "general protection", "kernel panic")
DHCP_TOKENS   = ("dhclient:", "dhcpcd:", "bound to ", "lease of ", "dhcp ack")
TIME_TOKENS   = ("ntpd:", "chronyd:", "systemd-timesyncd:", "time step of",
                 "clock step", "adjusting clock")
DISK_TOKENS   = ("ext4-fs error", "xfs error", "i/o error",
                 "read-only filesystem", "journal aborted",
                 "remounting filesystem read-only")
NET_CHANGE_TOKENS = ("link is not ready", "link becomes ready",
                     "carrier lost", "entered promiscuous mode")

# Fast-reject gate: one flat tuple of EVERY detection token (suspicious +
# all kernel/system categories below). The vast majority of syslog lines
# match none of these; a single `any(t in low ...)` pass over this tuple
# short-circuits them and lets us skip the ~10 per-category checks. It is a
# strict superset of those categories, so detection output is unchanged: if
# the gate misses, none of the categories could have matched either.
# Plain `in` checks beat a compiled alternation regex here — see
# core.utils.find_suspicious_tokens for the rationale.
_ALL_DETECT_TOKENS = (
    SUSPICIOUS_TOKENS + OOM_TOKENS + USB_TOKENS + SELINUX_TOKENS
    + APPARMOR_TOKENS + CRASH_TOKENS + DHCP_TOKENS + TIME_TOKENS
    + DISK_TOKENS + NET_CHANGE_TOKENS
)

# Map filename suffix -> (logical source label, expected family base name
# for find_log_family). The base name is what wtmp.find_log_family
# searches for, so e.g. "messages" matches messages, messages.1,
# messages.2.gz, messages-20240901, etc.
_FAMILIES = (
    ("messages",   "messages"),
    ("syslog",     "syslog"),
    ("kern.log",   "kern.log"),
    ("dmesg",      "dmesg"),
    ("boot.log",   "boot.log"),
    ("cron.log",   "cron.log"),
    ("cron",       "cron"),       # keep AFTER cron.log
    ("maillog",    "maillog"),
    ("mail.log",   "mail.log"),
    ("mail.err",   "mail.err"),
    ("daemon.log", "daemon.log"),
    ("user.log",   "user.log"),
    ("debug",      "debug"),
)


class SyslogParser(BaseParser):
    name = "syslog"

    def run(self) -> None:
        seen_paths: set[Path] = set()

        # crash-cluster counters, per source file
        crash_counts: Counter[tuple[str, str]] = Counter()

        for label, base in _FAMILIES:
            for path in self.finder.find_log_family(base):
                # protect against the same physical file matching twice
                # (e.g. "cron" base also matching "cron.log" path)
                if path in seen_paths:
                    continue
                # disambiguate "cron" vs "cron.log": only accept "cron"
                # entries whose actual filename starts with cron and is
                # NOT a cron.log* file.
                if label == "cron" and "cron.log" in path.name:
                    continue
                seen_paths.add(path)
                self.note_file(path)
                self._parse_file(path, label=label, crash_counts=crash_counts)

        # ----- emit clustered findings after all files are read -----
        for (src_path, prog), n in crash_counts.items():
            if n >= 5:
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="stability_anomaly",
                    title=f"{n} crash/segfault events for '{prog}'",
                    description=(
                        f"Process '{prog}' produced {n} crash-class log "
                        f"messages (segfault / general protection / panic). "
                        "Repeated crashes can indicate exploit attempts or "
                        "memory-corruption bugs being triggered."
                    ),
                    artifact=src_path,
                    metadata={"program": prog, "count": n},
                )

    # ------------------------------------------------------------------
    def _parse_file(self, path: Path, label: str, crash_counts: Counter) -> None:
        # Some files are dmesg-style ([12.345678] msg) rather than syslog.
        # We auto-detect per line.
        path_mtime: datetime | None = None
        try:
            path_mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            pass

        for raw in read_lines(path):
            line = raw.rstrip()
            if not line:
                continue

            ts = parse_syslog_timestamp(line)
            host = None
            prog = None
            msg = None

            if ts is not None:
                # Strip the timestamp prefix and parse the body.
                # parse_syslog_timestamp matched at position 0; locate
                # the end of the timestamp by finding the first space
                # after the time component.
                rest = self._strip_ts_prefix(line)
                m = SYSLOG_BODY_RE.match(rest)
                if m:
                    host = m.group("host") or None
                    prog = m.group("prog") or None
                    msg = m.group("msg") or ""
                else:
                    msg = rest.strip()
            else:
                # Try dmesg style
                m = DMESG_RE.match(line)
                if m:
                    msg = m.group("msg")
                    ts = path_mtime  # dmesg lines are relative to boot
                    prog = "kernel"
                else:
                    # Skip line entirely if we can't anchor it in time
                    continue

            if ts is None:
                continue

            event_type = f"{label}:{prog}" if prog else label
            description = msg if msg else line

            self.emit_event(
                timestamp=ts,
                source=label,
                event_type=event_type,
                description=description[:500],
                user=None,
                host=host,
                metadata={"program": prog} if prog else {},
                raw=line,
            )

            low = (msg or "").lower()

            # ---- detections ------------------------------------------------
            # Fast-reject gate: only lines containing at least one detection
            # token pay for the ~10 per-category scans below. The tuple is a
            # strict superset of every category, so this is a performance
            # change only — the findings produced are identical. The timeline
            # event above is already emitted regardless.
            if not low or not any(t in low for t in _ALL_DETECT_TOKENS):
                continue

            hits = find_suspicious_tokens(low)
            if hits:
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="suspicious_command",
                    title=f"Suspicious tokens in {label} ({prog or 'unknown'})",
                    description=(
                        f"Log line contains tokens commonly seen in "
                        f"attacker tradecraft: {', '.join(hits)}."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line[:600]],
                    metadata={"program": prog, "tokens": hits},
                )

            if any(t in low for t in OOM_TOKENS):
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="resource_anomaly",
                    title="OOM killer activity",
                    description=(
                        "Kernel out-of-memory killer activity recorded. "
                        "Common during memory-exhaustion DoS, runaway "
                        "miners, or fork-bomb behaviour."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line[:600]],
                )

            if any(t in low for t in USB_TOKENS):
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="hardware_anomaly",
                    title="USB mass-storage attach",
                    description=(
                        "USB mass-storage device was attached. On servers "
                        "this is anomalous and may indicate physical "
                        "tampering or data exfiltration."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line[:600]],
                )

            if any(t in low for t in SELINUX_TOKENS):
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="mac_denial",
                    title="SELinux denial in syslog",
                    description=(
                        "SELinux denied an action. Investigate whether "
                        "the denial reflects mis-configuration or actual "
                        "attempted boundary violation."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line[:600]],
                )

            if any(t in low for t in APPARMOR_TOKENS):
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="mac_denial",
                    title="AppArmor denial in syslog",
                    description=(
                        "AppArmor denied an action - review the offending "
                        "profile and the process being confined."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line[:600]],
                )

            if any(t in low for t in CRASH_TOKENS):
                if prog:
                    crash_counts[(str(path), prog)] += 1

            if any(t in low for t in DHCP_TOKENS):
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="network_anomaly",
                    title="DHCP lease event",
                    description=(
                        "DHCP lease activity detected. IP address changes "
                        "may indicate rogue DHCP or network manipulation."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line[:600]],
                )

            if any(t in low for t in TIME_TOKENS):
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="timestamp_anomaly",
                    title="Time synchronization event",
                    description=(
                        "Time sync change detected (ntpd/chronyd/timesyncd). "
                        "Large time steps can indicate timestomping or "
                        "manipulated system clocks."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line[:600]],
                )

            if any(t in low for t in DISK_TOKENS):
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="storage_anomaly",
                    title="Disk/filesystem error",
                    description=(
                        "Filesystem error detected (EXT4/XFS I/O error, "
                        "read-only remount, journal abort). May indicate "
                        "disk tampering, wiping, or hardware failure."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line[:600]],
                )

            if any(t in low for t in NET_CHANGE_TOKENS):
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="network_anomaly",
                    title="Network interface state change",
                    description=(
                        "Network interface state change detected (link "
                        "up/down, promiscuous mode). Promiscuous mode may "
                        "indicate packet sniffing."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line[:600]],
                )

    # ------------------------------------------------------------------
    @staticmethod
    def _strip_ts_prefix(line: str) -> str:
        """Return the line with its leading syslog timestamp stripped."""
        # RFC5424: ISO timestamp ends at the first whitespace after the T...
        if line and line[0].isdigit():
            sp = line.find(" ")
            if sp > 0:
                return line[sp + 1:]
            return line
        # RFC3164: "Mon DD HH:MM:SS " - that's exactly 15 chars + a space
        # but day can be either 1 or 2 chars. Cheap path: split on " " up
        # to 4 tokens (mon, day, time, rest).
        parts = line.split(None, 3)
        if len(parts) >= 4:
            return parts[3]
        return line
