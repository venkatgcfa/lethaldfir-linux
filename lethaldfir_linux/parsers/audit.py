"""
parsers.audit
=============

Parses ``/var/log/audit/audit.log`` (and rotated siblings).

The auditd record format is one event per line, key=value pairs, with a
record type prefix like ``type=EXECVE``.

Extracted events
----------------
* type=USER_LOGIN / USER_AUTH / USER_START / USER_END
* type=EXECVE (command-line reconstruction)
* type=ADD_USER, DEL_USER, ADD_GROUP, DEL_GROUP
* type=ANOM_*    (kernel anomaly events)
* type=AVC       (SELinux denials)

Findings raised
---------------
* **HIGH**     ANOM_PROMISCUOUS, ANOM_ABEND with signal, AVC denials
* **HIGH**     EXECVE matching offensive tradecraft tokens
* **MEDIUM**   USER_AUTH res=failed
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_INFO, SEV_MEDIUM
from ..core.utils import find_suspicious_tokens, read_lines
from .base import BaseParser


# audit timestamp:    audit(1727715200.123:4567)
AUDIT_HDR_RE = re.compile(r"audit\((?P<epoch>\d+(?:\.\d+)?):(?P<serial>\d+)\)")
TYPE_RE      = re.compile(r"type=(?P<type>\S+)")
KV_RE        = re.compile(r'([a-zA-Z0-9_]+)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))')


class AuditParser(BaseParser):
    name = "audit"

    def run(self) -> None:
        files = self.finder.find_log_family("audit.log")
        seen: set[Path] = set()
        files = [f for f in files if not (f in seen or seen.add(f))]
        execve_records: list[dict] = []
        for f in files:
            self.note_file(f)
            self._parse_one(f, execve_records)

        # Write per-parser CSV
        self.write_csv("audit_execve.csv", execve_records,
                       ["timestamp", "cmdline", "auid", "uid",
                        "pid", "ppid", "source_file"])

    def _parse_one(self, path: Path, execve_records: list) -> None:
        for line in read_lines(path):
            tm = TYPE_RE.search(line)
            ht = AUDIT_HDR_RE.search(line)
            if not tm or not ht:
                continue
            try:
                ts = datetime.fromtimestamp(float(ht["epoch"]), tz=timezone.utc)
            except (ValueError, OSError):
                continue
            etype = tm["type"]
            kv = {k: (v1 or v2 or v3) for k, v1, v2, v3 in KV_RE.findall(line)}

            description = self._describe(etype, kv)
            self.emit_event(
                timestamp=ts,
                source="audit.log",
                event_type=f"audit_{etype.lower()}",
                description=description,
                user=kv.get("uid") or kv.get("auid"),
                raw=line,
                metadata={"audit_type": etype, **kv},
            )

            # Collect EXECVE for CSV
            if etype == "EXECVE":
                args = []
                i = 0
                while True:
                    key = f"a{i}"
                    if key not in kv:
                        break
                    args.append(kv[key])
                    i += 1
                if args:
                    execve_records.append({
                        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                        "cmdline": " ".join(args),
                        "auid": kv.get("auid", ""),
                        "uid": kv.get("uid", ""),
                        "pid": kv.get("pid", ""),
                        "ppid": kv.get("ppid", ""),
                        "source_file": str(path),
                    })

            self._evaluate(etype, kv, line, path, ts)

    # ------------------------------------------------------------------
    @staticmethod
    def _describe(etype: str, kv: dict) -> str:
        if etype == "EXECVE":
            args = []
            i = 0
            while True:
                key = f"a{i}"
                if key not in kv:
                    break
                args.append(kv[key])
                i += 1
            return f"EXECVE: {' '.join(args)}" if args else f"EXECVE record"
        if etype.startswith("USER_"):
            return (
                f"{etype} acct={kv.get('acct','?')} res={kv.get('res','?')} "
                f"addr={kv.get('addr','-')} terminal={kv.get('terminal','-')}"
            )
        if etype == "AVC":
            return (
                f"AVC denied: {kv.get('comm','?')} -> "
                f"{kv.get('tcontext','-')} ({kv.get('scontext','-')})"
            )
        return f"{etype} " + " ".join(f"{k}={v}" for k, v in list(kv.items())[:8])

    def _evaluate(
        self, etype: str, kv: dict, line: str, path: Path, ts: datetime
    ) -> None:
        if etype == "EXECVE":
            args = []
            i = 0
            while True:
                key = f"a{i}"
                if key not in kv:
                    break
                args.append(kv[key])
                i += 1
            if args:
                cmdline = " ".join(args)
                hits = find_suspicious_tokens(cmdline)
                if hits:
                    self.emit_finding(
                        severity=SEV_HIGH,
                        category="execution",
                        title="Suspicious EXECVE in auditd",
                        description=(
                            f"auditd recorded an EXECVE containing tokens "
                            f"associated with attacker tradecraft: {', '.join(hits)}."
                        ),
                        artifact=str(path),
                        timestamp=ts,
                        evidence=[cmdline],
                    )

        elif etype == "AVC":
            if kv.get("denied") or "denied" in line.lower():
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="defense_evasion",
                    title=f"SELinux denial: {kv.get('comm','?')}",
                    description=(
                        f"SELinux blocked process {kv.get('comm','?')} "
                        f"(scontext={kv.get('scontext','-')}) accessing "
                        f"target context {kv.get('tcontext','-')}."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    evidence=[line.strip()],
                )

        elif etype.startswith("ANOM_"):
            self.emit_finding(
                severity=SEV_HIGH,
                category="anomaly",
                title=f"Kernel anomaly: {etype}",
                description=(
                    f"auditd recorded a kernel anomaly event ({etype}). "
                    "These typically indicate crashes, abends, or "
                    "promiscuous-mode interface changes."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[line.strip()],
            )

        elif etype.startswith("USER_") and kv.get("res", "").lower() == "failed":
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="credential_access",
                title=f"Auditd authentication failure ({etype})",
                description=(
                    f"Authentication failure recorded by auditd for "
                    f"acct={kv.get('acct','?')} from {kv.get('addr','-')}."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[line.strip()],
            )

        elif etype == "CONFIG_CHANGE":
            self.emit_finding(
                severity=SEV_HIGH,
                category="defense_evasion",
                title="Audit configuration changed",
                description=(
                    "auditd rules were modified at runtime. An attacker "
                    "may be disabling audit rules to evade detection."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[line.strip()],
            )

        elif etype in ("DAEMON_END", "DAEMON_ABORT"):
            self.emit_finding(
                severity=SEV_HIGH,
                category="defense_evasion",
                title=f"Audit daemon stopped: {etype}",
                description=(
                    f"auditd daemon was stopped ({etype}). Stopping the "
                    "audit daemon is a common anti-forensic technique."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=[line.strip()],
            )
