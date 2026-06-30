"""
parsers.host_metadata
=====================

Parses host-level configuration files to populate ``case.host_info`` and
emit informational events:

* ``/etc/hostname``
* ``/etc/os-release``, ``/etc/lsb-release``, ``/etc/redhat-release``
* ``/etc/hosts``         - findings for non-RFC1918 mappings shadowing real domains
* ``/etc/resolv.conf``   - findings for unusual DNS servers
* ``/etc/fstab``
* ``/etc/network/interfaces``, ``/etc/sysconfig/network-scripts/ifcfg-*``
* iptables-save / nftables dumps if present in evidence
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.event import SEV_LOW, SEV_MEDIUM
from ..core.utils import read_lines
from .base import BaseParser


PRIVATE_DNS_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "169.254.", "fe80:",
)


class HostMetadataParser(BaseParser):
    name = "host_metadata"

    def run(self) -> None:
        # hostname
        for f in self.finder.find_by_suffix(["/etc/hostname"]):
            self.note_file(f)
            for line in read_lines(f):
                if line.strip():
                    self.case.host_info["hostname"] = line.strip()
                    break

        # os-release
        for f in self.finder.find_by_suffix(["/etc/os-release"]):
            self.note_file(f)
            data: dict[str, str] = {}
            for line in read_lines(f):
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip().strip('"')
            if data:
                self.case.host_info["os_release"] = data
                self.case.host_info["distro"] = data.get("PRETTY_NAME") \
                    or data.get("NAME") or self.case.host_info.get("distro")

        for f in self.finder.find_by_suffix(["/etc/redhat-release"]):
            self.note_file(f)
            for line in read_lines(f):
                if line.strip():
                    self.case.host_info["distro"] = line.strip()
                    break

        for f in self.finder.find_by_suffix(["/etc/lsb-release"]):
            self.note_file(f)
            data: dict[str, str] = {}
            for line in read_lines(f):
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip().strip('"')
            if data and not self.case.host_info.get("distro"):
                self.case.host_info["distro"] = data.get("DISTRIB_DESCRIPTION") or \
                    data.get("DISTRIB_ID")

        # hosts
        for f in self.finder.find_by_suffix(["/etc/hosts"]):
            self.note_file(f)
            self._parse_hosts(f)

        # resolv.conf
        for f in self.finder.find_by_suffix(["/etc/resolv.conf"]):
            self.note_file(f)
            self._parse_resolv(f)

        # fstab
        for f in self.finder.find_by_suffix(["/etc/fstab"]):
            self.note_file(f)
            ts = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc) \
                if f.exists() else datetime.now(timezone.utc)
            for line in read_lines(f):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                self.emit_event(
                    timestamp=ts,
                    source="fstab",
                    event_type="fstab_entry",
                    description=f"fstab: {line}",
                    metadata={"line": line},
                    raw=line,
                )

        # network IP detection
        self._parse_network()

    # ------------------------------------------------------------------
    def _parse_hosts(self, path: Path) -> None:
        ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc) \
            if path.exists() else datetime.now(timezone.utc)
        suspicious_hosts: list[str] = []
        for line in read_lines(path):
            ls = line.strip()
            if not ls or ls.startswith("#"):
                continue
            parts = ls.split()
            if len(parts) < 2:
                continue
            ip = parts[0]
            names = parts[1:]
            self.emit_event(
                timestamp=ts,
                source="/etc/hosts",
                event_type="hosts_entry",
                description=f"/etc/hosts: {ip} -> {', '.join(names)}",
                metadata={"ip": ip, "names": names},
                raw=ls,
            )
            for n in names:
                low = n.lower()
                if any(susp in low for susp in (
                    "google", "github", "microsoft", "windowsupdate",
                    "apple", "amazon", "cloudflare", "bank",
                )):
                    if not any(ip.startswith(p) for p in ("127.", "::1", "0.0.0.0")):
                        suspicious_hosts.append(ls)
        if suspicious_hosts:
            self.emit_finding(
                severity=SEV_MEDIUM,
                category="defense_evasion",
                title="/etc/hosts redirects well-known domains",
                description=(
                    "Entries in /etc/hosts redirect well-known service "
                    "domains (Google, GitHub, banking, update services) to "
                    "non-loopback IPs. This can be used for credential theft "
                    "or update-poisoning."
                ),
                artifact=str(path),
                timestamp=ts,
                evidence=suspicious_hosts,
            )

    def _parse_resolv(self, path: Path) -> None:
        ts = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc) \
            if path.exists() else datetime.now(timezone.utc)
        ns = []
        for line in read_lines(path):
            ls = line.strip()
            if ls.startswith("nameserver"):
                parts = ls.split()
                if len(parts) >= 2:
                    ns.append(parts[1])
        for server in ns:
            self.emit_event(
                timestamp=ts,
                source="resolv.conf",
                event_type="dns_server",
                description=f"resolv.conf nameserver: {server}",
                metadata={"server": server},
            )
            if not any(server.startswith(p) for p in PRIVATE_DNS_PREFIXES) and \
                    server not in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                                    "9.9.9.9", "208.67.222.222", "208.67.220.220"):
                self.emit_finding(
                    severity=SEV_LOW,
                    category="network_config",
                    title=f"Unusual DNS resolver: {server}",
                    description=(
                        f"resolv.conf contains nameserver {server} which is "
                        "not a well-known public resolver or private-range "
                        "address. Verify this is expected for the environment."
                    ),
                    artifact=str(path),
                    timestamp=ts,
                    metadata={"server": server},
                )

    # ------------------------------------------------------------------
    def _parse_network(self) -> None:
        """Detect host IP addresses from network configuration sources."""
        # ----- Host IP detection -----
        # Walk a handful of network-config sources, dedup, and stash on
        # case.host_info so the Summary section / report can render it.
        ip_addrs: list[dict] = []

        # /etc/network/interfaces (Debian/Ubuntu legacy ifupdown)
        for f in self.finder.find_by_suffix(["/etc/network/interfaces"]):
            self.note_file(f)
            iface = None
            for line in read_lines(f):
                ls = line.strip()
                m = re.match(r"^iface\s+(\S+)\s+inet\s+\S+", ls)
                if m:
                    iface = m.group(1)
                    continue
                m = re.match(r"^address\s+(\S+)", ls)
                if m and iface:
                    ip_addrs.append({"iface": iface, "ip": m.group(1).split("/")[0],
                                     "source": "interfaces"})

        # /etc/network/interfaces.d/*
        for f in self.finder.find_by_glob(["**/etc/network/interfaces.d/*"]):
            self.note_file(f)
            iface = None
            for line in read_lines(f):
                ls = line.strip()
                m = re.match(r"^iface\s+(\S+)", ls)
                if m:
                    iface = m.group(1); continue
                m = re.match(r"^address\s+(\S+)", ls)
                if m and iface:
                    ip_addrs.append({"iface": iface, "ip": m.group(1).split("/")[0],
                                     "source": "interfaces.d"})

        # /etc/sysconfig/network-scripts/ifcfg-* (RHEL/CentOS legacy)
        for f in self.finder.find_by_glob(
                ["**/etc/sysconfig/network-scripts/ifcfg-*"]):
            if f.name.endswith((".bak", ".orig", ".rpmsave", ".rpmnew")):
                continue
            self.note_file(f)
            cfg: dict[str, str] = {}
            for line in read_lines(f):
                ls = line.strip()
                if "=" in ls and not ls.startswith("#"):
                    k, v = ls.split("=", 1)
                    cfg[k.strip()] = v.strip().strip('"')
            iface = cfg.get("DEVICE") or f.name.replace("ifcfg-", "")
            for k in ("IPADDR", "IPADDR0", "IPADDR1", "IPV6ADDR"):
                if cfg.get(k):
                    ip_addrs.append({"iface": iface,
                                     "ip": cfg[k].split("/")[0],
                                     "source": "ifcfg"})

        # /etc/netplan/*.yaml (modern Ubuntu) - lightweight regex parsing,
        # no PyYAML dependency
        for f in self.finder.find_by_glob(["**/etc/netplan/*.yaml",
                                           "**/etc/netplan/*.yml"]):
            self.note_file(f)
            current_iface = None
            for line in read_lines(f):
                m = re.match(r"^\s{4,8}([a-zA-Z0-9_-]+):\s*$", line)
                if m and not line.lstrip().startswith(("dhcp", "addresses",
                                                        "gateway", "routes",
                                                        "nameservers")):
                    current_iface = m.group(1)
                    continue
                m = re.search(r"-\s+([0-9a-fA-F:.]+/\d+)", line)
                if m and current_iface:
                    ip_addrs.append({"iface": current_iface,
                                     "ip": m.group(1).split("/")[0],
                                     "source": "netplan"})

        # NetworkManager keyfiles
        for f in self.finder.find_by_glob([
                "**/etc/NetworkManager/system-connections/*",
                "**/var/lib/NetworkManager/*"]):
            if not f.is_file():
                continue
            self.note_file(f)
            current_iface = None
            in_section = None
            for line in read_lines(f):
                ls = line.strip()
                if ls.startswith("[") and ls.endswith("]"):
                    in_section = ls[1:-1]
                    continue
                if "=" not in ls:
                    continue
                k, v = ls.split("=", 1)
                k = k.strip(); v = v.strip()
                if k == "interface-name":
                    current_iface = v
                elif in_section in ("ipv4", "ipv6") and k.startswith("address"):
                    ip = v.split(",")[0].split("/")[0]
                    if ip:
                        ip_addrs.append({"iface": current_iface or "(nm)",
                                         "ip": ip, "source": "NetworkManager"})

        # /etc/hosts entries that point at the local hostname (heuristic)
        hostname = self.case.host_info.get("hostname")
        if hostname:
            for f in self.finder.find_by_suffix(["/etc/hosts"]):
                for line in read_lines(f):
                    parts = line.split()
                    if len(parts) >= 2 and any(
                            h == hostname or h.startswith(hostname + ".")
                            for h in parts[1:]):
                        ip = parts[0]
                        if ip and ip not in ("127.0.0.1", "::1", "127.0.1.1"):
                            ip_addrs.append({"iface": "(hosts-file)",
                                             "ip": ip, "source": "/etc/hosts"})

        # Dedup, preserve discovery order
        seen = set()
        deduped = []
        for entry in ip_addrs:
            key = (entry["iface"], entry["ip"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(entry)
        if deduped:
            self.case.host_info["ip_addresses"] = deduped
            for e in deduped:
                self.emit_event(
                    timestamp=datetime.now(timezone.utc),
                    source="host_metadata",
                    event_type="host_ip",
                    description=(
                        f"Host IP: {e['ip']} on {e['iface']} "
                        f"(from {e['source']})"
                    ),
                    metadata=e,
                )