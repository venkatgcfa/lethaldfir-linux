"""
parsers.container_logs
======================

Parses Docker and Podman container logs and daemon events.

Files: /var/lib/docker/containers/<id>/*-json.log,
       /var/log/containers/*.log, Docker/Podman daemon logs.

Findings: HIGH for --privileged, host mounts, crypto-miner images.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_HIGH, SEV_MEDIUM
from ..core.utils import find_suspicious_tokens, read_lines
from .base import BaseParser

MINER_INDICATORS = ("xmrig", "stratum+tcp", "monero", "minergate",
                    "cryptonight", "hashrate", "mining pool")
SUSPICIOUS_IMAGES = ("alpine", "busybox", "ubuntu")  # when run privileged


class ContainerLogsParser(BaseParser):
    name = "container_logs"

    def run(self) -> None:
        # Docker JSON logs
        for f in self.finder.find_by_glob([
            "**/var/lib/docker/containers/**/*-json.log",
        ]):
            if f.is_file():
                self.note_file(f)
                self._parse_docker_json(f)

        # Podman/CRI-O container logs
        for f in self.finder.find_by_glob([
            "**/var/log/containers/*.log",
            "**/var/log/pods/**/*.log",
        ]):
            if f.is_file():
                self.note_file(f)
                self._parse_container_log(f)

        # Docker daemon log
        for f in self.finder.find_log_family("docker.log"):
            self.note_file(f)
            self._parse_daemon_log(f)
        for f in self.finder.find_log_family("dockerd.log"):
            self.note_file(f)
            self._parse_daemon_log(f)

        # Docker config for daemon settings
        for f in self.finder.find_by_suffix(["/etc/docker/daemon.json"]):
            self.note_file(f)
            self._parse_daemon_config(f)

    def _parse_docker_json(self, path: Path) -> None:
        """Docker JSON log: {"log":"...\n","stream":"...","time":"..."}"""
        for line in read_lines(path):
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            ts_str = rec.get("time", "")
            log_msg = rec.get("log", "").rstrip("\n")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                ts = datetime.now(timezone.utc)

            self.emit_event(
                timestamp=ts, source="docker_container",
                event_type="container_log",
                description=log_msg[:300], raw=line,
                metadata={"stream": rec.get("stream", ""),
                           "container_log": str(path)},
            )

            low = log_msg.lower()
            if any(m in low for m in MINER_INDICATORS):
                self.emit_finding(
                    severity=SEV_HIGH, category="execution",
                    title="Crypto-miner indicator in container log",
                    description=(
                        "Container log output contains crypto-mining indicators."
                    ),
                    artifact=str(path), timestamp=ts,
                    evidence=[log_msg[:500]],
                )
            hits = find_suspicious_tokens(log_msg)
            if hits:
                self.emit_finding(
                    severity=SEV_HIGH, category="suspicious_command",
                    title="Suspicious tokens in container log",
                    description=f"Tokens: {', '.join(hits)}",
                    artifact=str(path), timestamp=ts,
                    evidence=[log_msg[:500]],
                )

    def _parse_container_log(self, path: Path) -> None:
        """CRI/Podman log: timestamp stream F/P message"""
        for line in read_lines(path):
            parts = line.split(" ", 3)
            if len(parts) < 4:
                continue
            try:
                ts = datetime.fromisoformat(parts[0].replace("Z", "+00:00"))
            except ValueError:
                continue
            msg = parts[3] if len(parts) > 3 else ""
            self.emit_event(
                timestamp=ts, source="container_log",
                event_type="container_log",
                description=msg[:300], raw=line,
            )

    def _parse_daemon_log(self, path: Path) -> None:
        """Scan Docker/Podman daemon logs for security events."""
        for line in read_lines(path):
            low = line.lower()
            if "privileged" in low and ("create" in low or "start" in low):
                self.emit_finding(
                    severity=SEV_HIGH, category="privilege_escalation",
                    title="Privileged container launched",
                    description=(
                        "Docker/Podman daemon log shows a privileged "
                        "container being created or started."
                    ),
                    artifact=str(path),
                    evidence=[line.strip()[:500]],
                )

    def _parse_daemon_config(self, path: Path) -> None:
        """Check /etc/docker/daemon.json for insecure settings."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            config = json.loads(content)
        except (OSError, json.JSONDecodeError):
            return
        ts = datetime.now(timezone.utc)
        if config.get("insecure-registries"):
            self.emit_finding(
                severity=SEV_MEDIUM, category="defense_evasion",
                title="Docker insecure registries configured",
                description=(
                    f"daemon.json allows insecure registries: "
                    f"{config['insecure-registries']}"
                ),
                artifact=str(path), timestamp=ts,
                metadata={"registries": config["insecure-registries"]},
            )
