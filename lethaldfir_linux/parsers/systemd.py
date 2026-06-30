"""
parsers.systemd
===============

Walks the standard systemd unit search paths and parses every
``.service`` and ``.timer`` file:

* ``/etc/systemd/system/``      (admin-installed, highest precedence)
* ``/etc/systemd/system/*.wants/``
* ``/run/systemd/system/``
* ``/usr/lib/systemd/system/``  (vendor)
* ``/lib/systemd/system/``

Findings raised
---------------
* **HIGH**     ExecStart contains tokens such as ``curl ... | sh``,
               ``nc -e``, ``/dev/tcp/``, base64 decode, etc.
* **HIGH**     Unit installed under ``/etc/systemd/system`` whose ExecStart
               points into ``/tmp``, ``/var/tmp`` or ``/dev/shm``
* **MEDIUM**   Unit overrides a vendor file (etc copy with same name as lib copy)
* **INFO**     Per-unit inventory event with parsed ExecStart, User, Type
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import find_suspicious_tokens, read_lines
from .base import BaseParser


UNIT_DIRS = (
    "/etc/systemd/system/",
    "/run/systemd/system/",
    "/usr/lib/systemd/system/",
    "/lib/systemd/system/",
)


SUSPICIOUS_PATHS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")


class SystemdParser(BaseParser):
    name = "systemd"

    def run(self) -> None:
        units_by_name: dict[str, list[Path]] = {}
        files = self.finder.find_by_glob([
            "**/etc/systemd/system/**/*.service",
            "**/etc/systemd/system/**/*.timer",
            "**/run/systemd/system/**/*.service",
            "**/run/systemd/system/**/*.timer",
            "**/usr/lib/systemd/system/**/*.service",
            "**/usr/lib/systemd/system/**/*.timer",
            "**/lib/systemd/system/**/*.service",
            "**/lib/systemd/system/**/*.timer",
        ])
        seen: set[Path] = set()
        files = [f for f in files if f.is_file() and not (f in seen or seen.add(f))]

        parsed = []
        for path in files:
            self.note_file(path)
            unit = self._parse_unit(path)
            if unit:
                parsed.append(unit)
                units_by_name.setdefault(unit["name"], []).append(path)

        # ---- vendor-override detection ----
        for name, paths in units_by_name.items():
            in_etc = [p for p in paths if "/etc/systemd/system/" in p.as_posix()]
            in_lib = [p for p in paths if ("/usr/lib/systemd/system/" in p.as_posix()
                                            or "/lib/systemd/system/" in p.as_posix())]
            if in_etc and in_lib:
                try:
                    mtime = datetime.fromtimestamp(in_etc[0].stat().st_mtime, tz=timezone.utc)
                except OSError:
                    mtime = datetime.now(timezone.utc)
                self.emit_finding(
                    severity=SEV_MEDIUM,
                    category="persistence",
                    title=f"Vendor systemd unit overridden: {name}",
                    description=(
                        f"Unit '{name}' has an override in /etc/systemd/system/ "
                        "shadowing the vendor unit. Confirm the override is "
                        "an authorised change."
                    ),
                    artifact=str(in_etc[0]),
                    timestamp=mtime,
                    evidence=[str(p) for p in paths],
                )

        self.case.set_artifact("systemd_units", parsed)

    # ------------------------------------------------------------------
    def _parse_unit(self, path: Path):
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        section = ""
        kv: dict[str, list[str]] = {}
        for raw in read_lines(path):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            kv.setdefault(f"{section}.{k.strip()}", []).append(v.strip())

        unit = {
            "name": path.name,
            "path": str(path),
            "exec_start": kv.get("Service.ExecStart", []),
            "exec_start_pre": kv.get("Service.ExecStartPre", []),
            "user": (kv.get("Service.User", [None]) or [None])[0],
            "type": (kv.get("Service.Type", [None]) or [None])[0],
            "wantedby": kv.get("Install.WantedBy", []),
            "description": (kv.get("Unit.Description", [""]) or [""])[0],
        }

        self.emit_event(
            timestamp=mtime,
            source="systemd",
            event_type="unit_present",
            description=(
                f"systemd unit: {unit['name']} ExecStart="
                f"{'; '.join(unit['exec_start']) or '-'}"
            ),
            metadata=unit,
        )

        # ---- evaluate ExecStart commands ----
        for cmd in unit["exec_start"] + unit["exec_start_pre"]:
            hits = find_suspicious_tokens(cmd)
            if hits:
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="persistence",
                    title=f"Suspicious ExecStart in systemd unit {unit['name']}",
                    description=(
                        "A systemd unit's ExecStart line contains tokens "
                        f"associated with malicious automation: {', '.join(hits)}."
                    ),
                    artifact=str(path),
                    timestamp=mtime,
                    evidence=[cmd],
                    metadata=unit,
                )
            if any(p in cmd for p in SUSPICIOUS_PATHS) and "/etc/systemd/system/" in path.as_posix():
                self.emit_finding(
                    severity=SEV_HIGH,
                    category="persistence",
                    title=f"systemd unit {unit['name']} runs binary from world-writable location",
                    description=(
                        f"ExecStart for unit '{unit['name']}' references a path in "
                        "/tmp, /var/tmp or /dev/shm. Legitimate services should "
                        "live under /usr/bin, /usr/local/bin, /opt, etc."
                    ),
                    artifact=str(path),
                    timestamp=mtime,
                    evidence=[cmd],
                    metadata=unit,
                )

        return unit
