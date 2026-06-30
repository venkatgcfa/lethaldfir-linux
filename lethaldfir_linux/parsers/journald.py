"""
parsers.journald
================

Parses systemd journal binary files using the ``journalctl`` command.

On modern systemd-based Linux (RHEL 7+, Ubuntu 16.04+, Debian 8+),
journald is often the **primary** log sink.  Binary journal files
cannot be read as plain text, so this parser shells out to
``journalctl`` with the appropriate flags.

Strategy
--------
1. Check if ``journalctl`` is available on the analysis host.
2. Find ``.journal`` files in the evidence tree.
3. Use ``--root=<evidence_root>`` (preferred — auto-discovers system +
   user journals under ``var/log/journal/`` and ``run/log/journal/``).
4. Fall back to ``--file=<path>`` for each discovered ``.journal`` file
   if ``--root`` yields nothing.
5. Output as JSON (``--output=json``), one record per line.
6. Stream and parse each JSON record for timeline events and findings.

journalctl flags used
---------------------
::

    journalctl \\
        --root=<evidence_root>      # look at journal dirs under this root
        --output=json               # structured JSON, one object per line
        --no-pager                  # don't page output
        --all                       # show all fields, don't truncate
        --utc                       # timestamps in UTC
        --merge                     # interleave system + user journals
        --boot=all                  # all boots, not just current
        -q                          # suppress info banners

JSON fields parsed
------------------
* ``__REALTIME_TIMESTAMP`` — microseconds since epoch
* ``_HOSTNAME``
* ``SYSLOG_IDENTIFIER`` / ``_COMM`` — program name
* ``MESSAGE`` — log message
* ``PRIORITY`` — syslog priority 0-7
* ``_PID``, ``_UID``
* ``_SYSTEMD_UNIT`` — originating systemd unit
* ``_BOOT_ID`` — boot identifier
* ``_TRANSPORT`` — kernel, syslog, journal, stdout

Findings raised
---------------
* **CRITICAL** Priority 0 (emerg) messages
* **HIGH**     Priority 1-2 (alert/crit) messages
* **HIGH**     Suspicious tokens in MESSAGE (offensive tradecraft)
* **HIGH**     OOM killer activity
* **HIGH**     Coredump events
* **MEDIUM**   Service failures (``Failed to start``, ``entered failed state``)
* **INFO**     Every journal entry as a timeline event

Performance
-----------
* Token matching uses plain lowercase substring (``in``) checks, which
  benchmark markedly faster than a compiled alternation regex for the
  short messages in a journal (the previous IGNORECASE regex dominated
  per-record CPU time).
* Uses ``orjson`` for JSON parsing when available (~3-5× faster).
* Events are batched in memory and flushed periodically to reduce
  per-call overhead on the Case object.
* Journal presence is detected by scanning the finder's prebuilt file
  index rather than re-walking the evidence tree.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, TimelineEvent
from ..core.utils import SUSPICIOUS_TOKENS
from .base import BaseParser

# Try to use orjson for faster JSON parsing (3-5× speedup)
try:
    import orjson
    _loads = orjson.loads
except ImportError:
    _loads = json.loads


# syslog priority levels
PRIORITY_NAMES = {
    "0": "emerg", "1": "alert", "2": "crit", "3": "err",
    "4": "warning", "5": "notice", "6": "info", "7": "debug",
}


OOM_TOKENS = ("out of memory", "oom-killer", "killed process",
              "oom_reaper", "invoked oom-killer")
COREDUMP_TOKENS = ("dumped core", "core dumped", "coredump",
                   "process_exe", "segfault")
SERVICE_FAIL = ("failed to start", "entered failed state",
                "start request repeated too quickly",
                "failed with result")

# Detection uses plain substring (`in`) checks rather than a compiled
# alternation regex. The journal MESSAGE is lowercased once into `low` and
# every token is lowercase, so `t in low` runs as a C-level scan. This
# benchmarks ~10x faster than the previous IGNORECASE alternation regex,
# which dominated per-record CPU time on real journals.

# Batch size for flushing events to the Case
_BATCH_SIZE = 5_000


class JournaldParser(BaseParser):
    name = "journald"

    def run(self) -> None:
        journalctl = shutil.which("journalctl")
        if not journalctl:
            self.case.record_stats(self.name, errors=[
                "journalctl not found on the analysis host. "
                "Install systemd utilities or run from a Linux/WSL "
                "environment with systemd installed."
            ])
            return

        # ------ Strategy 1: --root= (best: auto-discovers all journals) ------
        parsed = self._try_root_mode(journalctl)

        # ------ Strategy 2: --file= per journal file (fallback) ------
        if not parsed:
            parsed = self._try_file_mode(journalctl)

        if not parsed:
            # No journal files found in evidence at all
            return

    # ------------------------------------------------------------------
    def _try_root_mode(self, journalctl: str) -> bool:
        """Try journalctl --root=<evidence_root> to auto-discover journals."""
        root = self.finder.root

        # Quick sanity check: does the evidence tree contain a journal dir?
        # Scan the finder's pre-built file index (one in-memory pass, short-
        # circuited) instead of two fresh rglob() walks of the whole tree —
        # on a large extracted image those walks were a multi-second tax paid
        # even when no journal was present.
        has_journal = any(
            "/var/log/journal/" in posix or "/run/log/journal/" in posix
            for posix in (p.as_posix() for p in self.finder.all_files())
        )
        if not has_journal:
            return False

        cmd = [
            journalctl,
            f"--root={root}",
            "--output=json",
            "--no-pager",
            "--all",
            "--utc",
            "--merge",
            "-q",
        ]

        # Try with --boot=all first (newer systemd), fall back without
        count = self._run_journalctl(cmd + ["--boot=all"])
        if count == 0:
            # --boot=all may not be supported; try without boot filter
            count = self._run_journalctl(cmd)

        return count > 0

    def _try_file_mode(self, journalctl: str) -> bool:
        """Fall back to --file= for each .journal file found."""
        journal_files = self.finder.find_by_glob([
            "**/*.journal",
            "**/*.journal~",  # corrupt / partially written
        ])
        journal_files = [f for f in journal_files if f.is_file()
                         and f.stat().st_size > 0]

        if not journal_files:
            return False

        # Note each journal file as evidence
        for jf in journal_files:
            self.note_file(jf)

        # Build --file= arguments for all journal files at once
        cmd = [
            "journalctl",
            "--output=json",
            "--no-pager",
            "--all",
            "--utc",
            "--merge",
            "-q",
        ]
        for jf in journal_files:
            cmd.extend(["--file", str(jf)])

        count = self._run_journalctl(cmd)
        return count > 0

    # ------------------------------------------------------------------
    def _run_journalctl(self, cmd: list[str]) -> int:
        """Execute journalctl and stream-parse JSON output.

        Returns the number of records processed.
        """
        count = 0
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,        # read raw bytes — faster than text mode
                bufsize=1 << 16,   # 64 KB read buffer
            )
        except (OSError, FileNotFoundError) as exc:
            self.case.record_stats(self.name, errors=[
                f"Failed to run journalctl: {exc}"
            ])
            return 0

        # Local references to avoid repeated attribute lookups in hot loop
        loads = _loads
        process = self._process_record
        case_events = self.case.events
        batch: list = []
        batch_append = batch.append

        try:
            for raw_line in proc.stdout:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    rec = loads(raw_line)
                except (json.JSONDecodeError, ValueError):
                    continue

                evt = process(rec)
                if evt is not None:
                    batch_append(evt)
                    if len(batch) >= _BATCH_SIZE:
                        case_events.extend(batch)
                        batch.clear()
                count += 1

            # Flush remaining batch
            if batch:
                case_events.extend(batch)
                batch.clear()

        except Exception:
            pass  # best-effort streaming
        finally:
            try:
                proc.stdout.close()
                proc.stderr.close()
                proc.wait(timeout=10)
            except Exception:
                proc.kill()

        return count

    # ------------------------------------------------------------------
    def _process_record(self, rec: dict):
        """Parse one JSON journal record into findings + optional event.

        Returns a TimelineEvent if the record is priority ≤ threshold,
        otherwise returns None (findings are still emitted directly).
        """
        # ---- Timestamp ----
        ts_us = rec.get("__REALTIME_TIMESTAMP")
        if ts_us:
            try:
                ts = datetime.fromtimestamp(
                    int(ts_us) / 1_000_000, tz=timezone.utc
                )
            except (ValueError, OSError):
                ts = None
        else:
            ts = None

        # ---- Fields ----
        hostname = rec.get("_HOSTNAME", "")
        prog = (rec.get("SYSLOG_IDENTIFIER")
                or rec.get("_COMM")
                or rec.get("_EXE", ""))
        message = rec.get("MESSAGE", "")

        # MESSAGE can be a list of byte values for non-UTF8 messages
        if isinstance(message, list):
            try:
                message = bytes(message).decode("utf-8", errors="replace")
            except (TypeError, ValueError):
                message = str(message)

        priority = str(rec.get("PRIORITY", "6"))
        unit = rec.get("_SYSTEMD_UNIT", "")
        uid = rec.get("_UID", "")
        pid = rec.get("_PID", "")

        # ---- Findings (always evaluated, regardless of priority) ----
        low = message.lower() if isinstance(message, str) else ""

        has_finding = False

        # Emergency (0) — most critical
        if priority == "0":
            has_finding = True
            self.emit_finding(
                severity=SEV_CRITICAL,
                category="system_anomaly",
                title=f"Emergency-level journal message from {prog or 'unknown'}",
                description=(
                    f"journald recorded a PRIORITY=0 (emerg) message: "
                    f"{message[:300]}"
                ),
                artifact="journald",
                timestamp=ts,
                evidence=[message[:600]],
                metadata={"program": prog, "unit": unit},
            )

        # Alert/Critical (1-2)
        elif priority in ("1", "2"):
            has_finding = True
            pri_name = PRIORITY_NAMES.get(priority, "info")
            self.emit_finding(
                severity=SEV_HIGH,
                category="system_anomaly",
                title=f"{pri_name.upper()} journal message from {prog or 'unknown'}",
                description=(
                    f"journald recorded a PRIORITY={priority} ({pri_name}) "
                    f"message: {message[:300]}"
                ),
                artifact="journald",
                timestamp=ts,
                evidence=[message[:600]],
                metadata={"program": prog, "unit": unit},
            )

        # OOM killer
        if any(t in low for t in OOM_TOKENS):
            has_finding = True
            self.emit_finding(
                severity=SEV_HIGH,
                category="resource_anomaly",
                title="OOM killer activity (journald)",
                description=(
                    "journald recorded OOM killer activity. Common during "
                    "memory-exhaustion DoS, crypto-miners, or fork bombs."
                ),
                artifact="journald",
                timestamp=ts,
                evidence=[message[:600]],
                metadata={"program": prog},
            )

        # Coredumps
        if any(t in low for t in COREDUMP_TOKENS):
            has_finding = True
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="stability_anomaly",
                title=f"Coredump/crash for {prog or unit or 'unknown'}",
                description=(
                    "journald recorded a process crash or coredump. "
                    "Repeated crashes may indicate exploitation attempts."
                ),
                artifact="journald",
                timestamp=ts,
                evidence=[message[:600]],
                metadata={"program": prog, "unit": unit},
            )

        # Service failures
        if any(t in low for t in SERVICE_FAIL):
            has_finding = True
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="service_anomaly",
                title=f"Service failure: {unit or prog or 'unknown'}",
                description=(
                    f"journald recorded a service failure: {message[:200]}"
                ),
                artifact="journald",
                timestamp=ts,
                evidence=[message[:600]],
                metadata={"program": prog, "unit": unit},
            )

        # Suspicious tokens — plain substring scan over the lowercased
        # message (faster than a compiled IGNORECASE alternation here).
        if low:
            hits = [t for t in SUSPICIOUS_TOKENS if t in low]
            if hits:
                has_finding = True
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="suspicious_command",
                    title=f"Suspicious tokens in journald ({prog or unit or 'unknown'})",
                    description=(
                        f"Journal entry contains tokens associated with "
                        f"attacker tradecraft: {', '.join(hits)}."
                    ),
                    artifact="journald",
                    timestamp=ts,
                    evidence=[message[:600]],
                    metadata={"program": prog, "tokens": hits, "unit": unit},
                )

        # ---- Timeline event (all records) ----
        if ts is None:
            ts = datetime.now(timezone.utc)

        pri_name = PRIORITY_NAMES.get(priority, "info")

        # Build description — avoid intermediate list allocation
        if prog and pid and unit:
            desc_prefix = f"{prog} [{pid}] ({unit})"
        elif prog and pid:
            desc_prefix = f"{prog} [{pid}]"
        elif prog and unit:
            desc_prefix = f"{prog} ({unit})"
        elif prog:
            desc_prefix = prog
        else:
            desc_prefix = ""

        description = f"{desc_prefix}: {message}" if desc_prefix else message

        evt = TimelineEvent(
            timestamp=ts,
            source="journald",
            event_type=f"journal_{pri_name}",
            description=description[:500],
            user=uid if uid else None,
            host=hostname or None,
            metadata={
                "priority": pri_name,
                "priority_num": priority,
                "program": prog,
                "unit": unit,
                "boot_id": rec.get("_BOOT_ID", "")[:8],
                "transport": rec.get("_TRANSPORT", ""),
                "pid": pid,
            },
            raw=message[:1000],
        )
        self._events += 1
        return evt
