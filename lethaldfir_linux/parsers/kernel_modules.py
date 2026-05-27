"""
parsers.kernel_modules
======================

Checks kernel module persistence and configuration:

* ``/etc/modules``           — modules loaded at boot (Debian/Ubuntu)
* ``/etc/modules-load.d/*``  — systemd module load configs
* ``/etc/modprobe.d/*``      — module parameters and blacklists

Findings:
  HIGH: Module loaded from /tmp, /dev/shm, or user-writable paths
  MEDIUM: Module with suspicious name patterns (rootkit indicators)
  INFO: Each module entry emitted as timeline event
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import find_suspicious_tokens, read_lines
from .base import BaseParser

ROOTKIT_MODULE_NAMES = (
    "diamorphine", "reptile", "suterusu", "adore-ng", "knark",
    "heroin", "override", "bdvl", "beurk", "jynx", "azazel",
    "vlany", "brootus", "enyelkm", "phalanx", "suckit",
    "hp_accel",  # commonly spoofed name
)


class KernelModulesParser(BaseParser):
    name = "kernel_modules"

    def run(self) -> None:
        # /etc/modules
        for f in self.finder.find_by_suffix(["/etc/modules"]):
            self.note_file(f)
            self._parse_modules_file(f)

        # /etc/modules-load.d/*
        for f in self.finder.find_by_glob(["**/etc/modules-load.d/*"]):
            if f.is_file():
                self.note_file(f)
                self._parse_modules_file(f)

        # /etc/modprobe.d/*
        for f in self.finder.find_by_glob(["**/etc/modprobe.d/*"]):
            if f.is_file():
                self.note_file(f)
                self._parse_modprobe(f)

    def _parse_modules_file(self, path: Path) -> None:
        try:
            ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            ts = datetime.now(timezone.utc)

        for line in read_lines(path):
            ls = line.strip()
            if not ls or ls.startswith("#"):
                continue

            module_name = ls.split()[0]
            self.emit_event(
                timestamp=ts, source="kernel_modules",
                event_type="module_autoload",
                description=f"Kernel module auto-load: {module_name}",
                metadata={"module": module_name, "file": str(path)},
            )

            low = module_name.lower()
            for rk in ROOTKIT_MODULE_NAMES:
                if rk in low:
                    self.emit_finding(
                        severity=SEV_HIGH, category="persistence",
                        title=f"Known rootkit module name: {module_name}",
                        description=(
                            f"Module '{module_name}' matches the name of a "
                            f"known Linux rootkit ({rk}). Investigate "
                            "immediately."
                        ),
                        artifact=str(path), timestamp=ts,
                        evidence=[ls],
                    )
                    break

    def _parse_modprobe(self, path: Path) -> None:
        try:
            ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            ts = datetime.now(timezone.utc)

        for line in read_lines(path):
            ls = line.strip()
            if not ls or ls.startswith("#"):
                continue

            self.emit_event(
                timestamp=ts, source="modprobe.d",
                event_type="modprobe_config",
                description=f"modprobe.d: {ls}",
                metadata={"line": ls, "file": str(path)},
            )

            # install directive can run arbitrary commands
            if ls.startswith("install "):
                parts = ls.split(None, 2)
                if len(parts) >= 3:
                    cmd = parts[2]
                    hits = find_suspicious_tokens(cmd)
                    if hits or any(p in cmd for p in
                                   ("/tmp/", "/dev/shm/", "/var/tmp/")):
                        self.emit_finding(
                            severity=SEV_HIGH, category="persistence",
                            title=f"Suspicious modprobe install: {parts[1]}",
                            description=(
                                "A modprobe 'install' directive runs an "
                                "arbitrary command when the module is loaded. "
                                f"Command: {cmd}"
                            ),
                            artifact=str(path), timestamp=ts,
                            evidence=[ls],
                        )
