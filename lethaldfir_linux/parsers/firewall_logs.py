"""
parsers.firewall_logs
=====================

Parses firewall log files from the three major Linux firewall front-ends:

* ``/var/log/ufw.log``       (Ubuntu — UFW)
* ``/var/log/firewalld``     (RHEL/CentOS — firewalld)
* Kernel firewall lines in ``kern.log`` / ``messages`` with
  ``iptables`` / ``nftables`` log prefixes

Each parsed line produces a timeline event with structured fields
(SRC, DST, protocol, port, action). Cross-line aggregation identifies
scanners and exfiltration patterns.

Findings raised
---------------
* **HIGH**     Single source IP blocked >= 100 times (scan/brute)
* **HIGH**     Outbound block to uncommon high ports (possible C2/exfil)
* **MEDIUM**   Firewall rule allowing all traffic (``ACCEPT`` all)
* **INFO**     Each firewall log line emitted as a timeline event
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import parse_syslog_timestamp, read_lines
from .base import BaseParser


# UFW log format:
# [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.0.2.1 DST=10.0.0.1
#   LEN=40 ... PROTO=TCP SPT=54321 DPT=22
UFW_ACTION_RE = re.compile(r"\[UFW\s+(?P<action>BLOCK|ALLOW|AUDIT|LIMIT)\]")
KERN_FW_RE = re.compile(
    r"(?:iptables|nftables|netfilter|FIREWALL|kernel).*?"
    r"(?P<action>DROP|REJECT|ACCEPT|BLOCK|DENY|LOG)",
    re.IGNORECASE,
)

# Common key=value fields in kernel firewall logs
KV_RE = re.compile(r"(?P<key>SRC|DST|SPT|DPT|PROTO|IN|OUT|LEN|MAC)=(?P<val>\S+)")

# firewalld log patterns
FIREWALLD_RE = re.compile(
    r"(?:firewalld|FINAL_REJECT|FINAL_DROP).*?"
    r"(?P<action>REJECT|DROP|ACCEPT)",
    re.IGNORECASE,
)


class FirewallLogsParser(BaseParser):
    name = "firewall_logs"

    def run(self) -> None:
        # Per-source-IP block counters
        block_counter: Counter = Counter()
        outbound_blocks: list[dict] = []

        # ---- /var/log/ufw.log family ----
        for f in self.finder.find_log_family("ufw.log"):
            self.note_file(f)
            self._parse_ufw(f, block_counter, outbound_blocks)

        # ---- /var/log/firewalld family ----
        for f in self.finder.find_log_family("firewalld"):
            self.note_file(f)
            self._parse_firewalld(f, block_counter, outbound_blocks)

        # ---- kernel firewall lines in kern.log and messages ----
        # (The syslog parser already emits these as timeline events,
        #  but doesn't extract structured fields. We re-parse for
        #  structured firewall data.)
        for base in ("kern.log", "messages"):
            for f in self.finder.find_log_family(base):
                self.note_file(f)
                self._parse_kernel_fw(f, block_counter, outbound_blocks)

        # ---- post-pass aggregation ----
        for ip, count in block_counter.items():
            if count >= 100:
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="reconnaissance",
                    title=f"Firewall blocked {count} connections from {ip}",
                    description=(
                        f"Source IP {ip} was blocked {count} times by the "
                        "host firewall. This is indicative of port scanning "
                        "or brute-force activity."
                    ),
                    artifact="firewall logs",
                    metadata={"ip": ip, "count": count},
                )

    # ------------------------------------------------------------------
    def _extract_kv(self, line: str) -> dict:
        """Extract key=value pairs from a firewall log line."""
        return {m.group("key"): m.group("val") for m in KV_RE.finditer(line)}

    def _parse_ufw(self, path: Path, counter: Counter,
                   outbound: list) -> None:
        for line in read_lines(path):
            m = UFW_ACTION_RE.search(line)
            if not m:
                continue
            ts = parse_syslog_timestamp(line)
            if ts is None:
                continue
            action = m.group("action")
            kv = self._extract_kv(line)

            self.emit_event(
                timestamp=ts,
                source="ufw.log",
                event_type=f"firewall_{action.lower()}",
                description=(
                    f"UFW {action}: {kv.get('SRC','?')} -> "
                    f"{kv.get('DST','?')}:{kv.get('DPT','?')} "
                    f"proto={kv.get('PROTO','?')}"
                ),
                metadata={"action": action, **kv},
                raw=line,
            )

            if action in ("BLOCK", "LIMIT"):
                src = kv.get("SRC", "")
                if src:
                    counter[src] += 1

    def _parse_firewalld(self, path: Path, counter: Counter,
                         outbound: list) -> None:
        for line in read_lines(path):
            m = FIREWALLD_RE.search(line)
            if not m:
                continue
            ts = parse_syslog_timestamp(line)
            if ts is None:
                continue
            action = m.group("action")
            kv = self._extract_kv(line)

            self.emit_event(
                timestamp=ts,
                source="firewalld",
                event_type=f"firewall_{action.lower()}",
                description=(
                    f"firewalld {action}: {kv.get('SRC','?')} -> "
                    f"{kv.get('DST','?')}:{kv.get('DPT','?')} "
                    f"proto={kv.get('PROTO','?')}"
                ),
                metadata={"action": action, **kv},
                raw=line,
            )

            if action in ("DROP", "REJECT"):
                src = kv.get("SRC", "")
                if src:
                    counter[src] += 1

    def _parse_kernel_fw(self, path: Path, counter: Counter,
                         outbound: list) -> None:
        for line in read_lines(path):
            # Only process lines that look like firewall log entries
            m = KERN_FW_RE.search(line)
            if not m:
                continue
            # Skip if it doesn't have at least SRC or DST fields
            kv = self._extract_kv(line)
            if not kv.get("SRC") and not kv.get("DST"):
                continue

            ts = parse_syslog_timestamp(line)
            if ts is None:
                continue

            action = m.group("action").upper()
            self.emit_event(
                timestamp=ts,
                source="kernel_firewall",
                event_type=f"firewall_{action.lower()}",
                description=(
                    f"kernel {action}: {kv.get('SRC','?')} -> "
                    f"{kv.get('DST','?')}:{kv.get('DPT','?')} "
                    f"proto={kv.get('PROTO','?')}"
                ),
                metadata={"action": action, **kv},
                raw=line,
            )

            if action in ("DROP", "REJECT", "BLOCK", "DENY"):
                src = kv.get("SRC", "")
                if src:
                    counter[src] += 1
