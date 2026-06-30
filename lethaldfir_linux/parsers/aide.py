"""
parsers.aide
============

Parses AIDE (Advanced Intrusion Detection Environment) report logs found in
the evidence and folds file-integrity changes into the unified case as
findings + timeline events, plus a detailed per-parser CSV.

AIDE is a host-based file-integrity monitor: it compares the live filesystem
against a known-good database and reports added / removed / changed entries
with per-attribute diffs (perm, uid/gid, mtime/ctime, checksums, ...). Those
diffs are high-value DFIR signal — persistence drops, binary tampering,
setuid escalation, timestomping.

Sources (suffix/dir-matched, rotated + .gz/.bz2/.xz handled):
* ``/var/log/aide/aide.log`` (Debian/Ubuntu cron output) and variants
* ``/var/log/aide.log``

Findings raised
---------------
* **CRITICAL** High-severity change carrying a top-signal flag
  (setuid/setgid added, content changed while mtime stayed static, mtime
  predates ctime)
* **HIGH**     Change to a sensitive path (credentials, persistence, system
  binaries, kernel/boot) — mapped from AIDE severity + path rules
* **MEDIUM**   Change to config / web / writable-staging paths
* **INFO**     Every change recorded as a timeline event

Triage, not verdicts: AIDE records *state diffs*, never which process or
actor made a change. Anything unparseable is surfaced in
``csv/aide_parse_issues.csv`` rather than silently dropped.

Calibrated against AIDE 0.17.x ``report_format=plain`` (tolerant of 0.16
wording); JSON reports are parsed best-effort.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..core.event import (
    SEV_CRITICAL, SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_ORDER,
)
from ..core.utils import neutralize_formula, open_text, sha256_file
from .base import BaseParser


# ===========================================================================
# Data model
# ===========================================================================

# Forensically interesting attributes get dedicated old/new columns;
# everything else is still captured in ``changed_attrs_raw``.
TYPED_ATTRS = [
    "size", "bcount", "perm", "uid", "gid", "inode", "linkcount",
    "mtime", "ctime", "atime",
    "md5", "sha1", "sha256", "sha512", "rmd160", "tiger", "crc32",
    "acl", "xattrs", "selinux", "e2fsattrs", "filetype",
]

# AIDE detail-section label -> normalized key (case-insensitive, spaces
# stripped; multiple aliases per key for cross-version robustness).
ATTR_ALIASES = {
    "size": ["size"],
    "bcount": ["bcount", "blockcount", "blocks"],
    "perm": ["perm", "perms", "permissions", "mode"],
    "uid": ["uid", "user"],
    "gid": ["gid", "group"],
    "inode": ["inode", "ino"],
    "linkcount": ["linkcount", "lcount", "links", "linkcnt"],
    "mtime": ["mtime"],
    "ctime": ["ctime"],
    "atime": ["atime"],
    "md5": ["md5"],
    "sha1": ["sha1"],
    "sha256": ["sha256"],
    "sha512": ["sha512"],
    "rmd160": ["rmd160", "ripemd160"],
    "tiger": ["tiger"],
    "crc32": ["crc32", "crc32b"],
    "acl": ["acl"],
    "xattrs": ["xattrs", "xattr"],
    "selinux": ["selinux"],
    "e2fsattrs": ["e2fsattrs", "e2fsattr"],
    "filetype": ["filetype", "ftype"],
}

_NORM_LABEL = {}
for _key, _aliases in ATTR_ALIASES.items():
    for _a in _aliases:
        _NORM_LABEL[_a] = _key


@dataclass
class ChangeRecord:
    source_log: str = ""
    source_sha256: str = ""
    host: str = ""
    run_start: str = ""
    run_index: int = 0
    aide_version: str = ""
    change_type: str = ""          # Added / Removed / Changed
    entry_type: str = ""           # file / directory / symlink / ...
    file_path: str = ""
    summary_string: str = ""       # raw compact summarize-changes string
    changed_attrs: str = ""        # human list, e.g. "size, mtime, sha256"
    changed_attrs_raw: str = ""    # json of {label: {old,new}} for everything
    category: str = ""
    severity: str = ""
    mitre: str = ""
    flags: str = ""

    def __post_init__(self):
        for a in TYPED_ATTRS:
            setattr(self, f"{a}_old", "")
            setattr(self, f"{a}_new", "")


@dataclass
class RunResult:
    source_log: str = ""
    source_sha256: str = ""
    host: str = ""
    run_index: int = 0
    aide_version: str = ""
    report_format: str = "plain"
    run_start: str = ""
    run_end: str = ""
    run_seconds: str = ""
    total_entries: str = ""
    added: int = 0
    removed: int = 0
    changed: int = 0
    n_sensitive: int = 0
    n_high: int = 0
    n_medium: int = 0
    parse_status: str = "ok"       # ok / no_differences / partial / error
    note: str = ""


@dataclass
class ParseIssue:
    source_log: str = ""
    run_index: int = 0
    severity: str = "warning"
    message: str = ""
    excerpt: str = ""


def _asdict(obj) -> dict:
    """vars() of a dataclass instance — includes the dynamically-set typed
    ``<attr>_old`` / ``<attr>_new`` columns that dataclasses.asdict() drops."""
    return dict(vars(obj))


# ===========================================================================
# Segmentation: one log file -> many run records
# ===========================================================================

RE_START_TS = re.compile(r"^Start timestamp:\s*(.+?)\s*(?:\(AIDE\s+([0-9][^)]*)\))?\s*$")
RE_END_TS = re.compile(r"^End timestamp:\s*(.+?)\s*(?:\(run time:\s*([^)]*)\))?\s*$", re.I)
RE_CRON_END = re.compile(r"End of AIDE daily cron job at\s*(.+?)(?:,| run time|$)")


def segment_runs(text: str) -> List[Tuple[int, str]]:
    """Split a log file into (run_index, run_text) tuples. Handles JSON
    reports (whole-object) and concatenated plain reports."""
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return [(0, text)]

    lines = text.splitlines()
    start_idxs = [i for i, ln in enumerate(lines) if RE_START_TS.match(ln)]
    if not start_idxs:
        return [(0, text)]

    runs: List[Tuple[int, str]] = []
    for n, start in enumerate(start_idxs):
        end = start_idxs[n + 1] if n + 1 < len(start_idxs) else len(lines)
        runs.append((n, "\n".join(lines[start:end])))
    return runs


# ===========================================================================
# Plain-format run parser
# ===========================================================================

RE_SUMMARY_TOTAL = re.compile(r"Total number of (?:entries|files)\s*:\s*([0-9,]+)", re.I)
RE_SUMMARY_ADDED = re.compile(r"Added (?:entries|files)\s*:\s*([0-9,]+)", re.I)
RE_SUMMARY_REMOVED = re.compile(r"Removed (?:entries|files)\s*:\s*([0-9,]+)", re.I)
RE_SUMMARY_CHANGED = re.compile(r"Changed (?:entries|files)\s*:\s*([0-9,]+)", re.I)

RE_SECTION_ADDED = re.compile(r"^Added (?:entries|files)\s*:\s*$", re.I)
RE_SECTION_REMOVED = re.compile(r"^Removed (?:entries|files)\s*:\s*$", re.I)
RE_SECTION_CHANGED = re.compile(r"^Changed (?:entries|files)\s*:\s*$", re.I)
RE_SECTION_DETAIL = re.compile(r"^Detailed information about changes\s*:\s*$", re.I)
RE_SECTION_DBATTR = re.compile(r"^The attributes of the .*database", re.I)

RE_RULE = re.compile(r"^-{5,}\s*$")

# A grouped-section entry line: "<summary-string>: /absolute/path".
# The change string never contains "/", so the first ": /" is the boundary.
RE_ENTRY_LINE = re.compile(r"^(?P<sum>.*?):\s+(?P<path>/.*)$")

RE_DETAIL_HEAD = re.compile(
    r"^(?P<kind>File|Directory|Dir|Link|Symlink|Entry)\s*:\s*(?P<path>.+)$", re.I)
RE_DETAIL_ATTR = re.compile(r"^\s+(?P<label>[A-Za-z0-9_][A-Za-z0-9_ ]*?)\s*:\s*(?P<rest>.*)$")

ENTRY_TYPE_MAP = {
    "f": "file", "d": "directory", "l": "symlink", "L": "symlink",
    "c": "char-device", "b": "block-device", "p": "fifo", "s": "socket",
    "D": "door", "P": "port",
}


def _to_int(s: str) -> int:
    try:
        return int(s.replace(",", "").strip())
    except (ValueError, AttributeError):
        return 0


def _split_old_new(rest: str) -> Tuple[str, str, bool]:
    """Split a detail value on ' | ' (0.17 plain); fall back to ' , ' (0.16)."""
    if " | " in rest:
        left, _, right = rest.partition(" | ")
        return left.strip(), right.strip(), True
    m = re.match(r"^(.*?)\s+,\s+(.*)$", rest)
    if m:
        return m.group(1).strip(), m.group(2).strip(), True
    return rest.strip(), "", False


def parse_detail_block(lines: List[str]) -> Dict[str, Dict]:
    """Parse the 'Detailed information about changes' section. Handles
    multi-line wrapped base64 checksum values."""
    result: Dict[str, Dict] = {}
    cur_path: Optional[str] = None
    cur_attr: Optional[str] = None
    cur_label_raw: Optional[str] = None

    for raw in lines:
        if not raw.strip():
            cur_attr = None
            continue

        head = RE_DETAIL_HEAD.match(raw)
        if head and not raw.startswith((" ", "\t")):
            kind = head.group("kind").lower()
            kind = {"dir": "directory", "symlink": "symlink"}.get(kind, kind)
            cur_path = head.group("path").strip()
            result.setdefault(cur_path, {"_kind": kind, "_raw": {}})
            cur_attr = None
            cur_label_raw = None
            continue

        if cur_path is None:
            continue

        attr = RE_DETAIL_ATTR.match(raw)
        if attr:
            label_raw = attr.group("label").strip()
            norm = _NORM_LABEL.get(label_raw.lower().replace(" ", ""), None)
            old, new, _ = _split_old_new(attr.group("rest"))
            entry = result[cur_path]
            entry["_raw"][label_raw] = {"old": old, "new": new}
            if norm:
                entry[norm] = (old, new)
            cur_attr = norm
            cur_label_raw = label_raw
        else:
            # Continuation of a wrapped value (long base64 checksums).
            if cur_label_raw is not None:
                old_c, new_c, _ = _split_old_new(raw.strip())
                entry = result[cur_path]
                rd = entry["_raw"].setdefault(cur_label_raw, {"old": "", "new": ""})
                rd["old"] += old_c
                rd["new"] += new_c
                if cur_attr:
                    o, nw = entry.get(cur_attr, ("", ""))
                    entry[cur_attr] = (o + old_c, nw + new_c)
    return result


def parse_grouped_section(lines: List[str]) -> List[Tuple[str, str]]:
    """Parse an Added/Removed/Changed grouped section -> [(summary, path)]."""
    out = []
    for raw in lines:
        if not raw.strip() or RE_RULE.match(raw):
            continue
        m = RE_ENTRY_LINE.match(raw)
        if m:
            out.append((m.group("sum").rstrip(), m.group("path").strip()))
    return out


def entry_type_from_summary(summary: str) -> str:
    if not summary:
        return ""
    return ENTRY_TYPE_MAP.get(summary[0], "")


def parse_plain_run(run_idx: int, run_text: str, src: str, sha: str,
                    issues: List[ParseIssue]) -> Tuple[RunResult, List[ChangeRecord]]:
    lines = run_text.splitlines()
    run = RunResult(source_log=src, source_sha256=sha, run_index=run_idx)

    m = RE_START_TS.match(lines[0]) if lines else None
    if m:
        run.run_start = m.group(1).strip()
        run.aide_version = (m.group(2) or "").strip()

    no_diff = any("found NO differences" in ln or "found no differences" in ln
                  or "Looks okay" in ln for ln in lines)

    idx_added = idx_removed = idx_changed = idx_detail = idx_dbattr = None
    for i, ln in enumerate(lines):
        if idx_added is None and RE_SECTION_ADDED.match(ln):
            idx_added = i
        elif idx_removed is None and RE_SECTION_REMOVED.match(ln):
            idx_removed = i
        elif idx_changed is None and RE_SECTION_CHANGED.match(ln):
            idx_changed = i
        elif idx_detail is None and RE_SECTION_DETAIL.match(ln):
            idx_detail = i
        elif idx_dbattr is None and RE_SECTION_DBATTR.match(ln):
            idx_dbattr = i

        ms = RE_SUMMARY_TOTAL.search(ln)
        if ms:
            run.total_entries = ms.group(1).replace(",", "")
        for rgx, attr in ((RE_SUMMARY_ADDED, "added"),
                          (RE_SUMMARY_REMOVED, "removed"),
                          (RE_SUMMARY_CHANGED, "changed")):
            mm = rgx.search(ln)
            if mm:
                setattr(run, attr, _to_int(mm.group(1)))

        me = RE_END_TS.match(ln)
        if me:
            run.run_end = me.group(1).strip()
            run.run_seconds = (me.group(2) or "").strip()
    if not run.run_end:
        for ln in lines:
            mc = RE_CRON_END.search(ln)
            if mc:
                run.run_end = mc.group(1).strip()
                break

    if no_diff and not any(x is not None for x in (idx_added, idx_removed, idx_changed)):
        run.parse_status = "no_differences"
        return run, []

    section_starts = sorted(x for x in (idx_added, idx_removed, idx_changed,
                                        idx_detail, idx_dbattr) if x is not None)

    def section_body(start: Optional[int]) -> List[str]:
        if start is None:
            return []
        b = start + 1
        nxt = next((s for s in section_starts if s > start), len(lines))
        body = lines[b:nxt]
        while body and (RE_RULE.match(body[0]) or not body[0].strip()):
            body.pop(0)
        return body

    detail = parse_detail_block(section_body(idx_detail)) if idx_detail is not None else {}

    records: List[ChangeRecord] = []

    def build_record(change_type: str, summary: str, path: str):
        rec = ChangeRecord(
            source_log=src, source_sha256=sha, host=run.host,
            run_start=run.run_start, run_index=run_idx,
            aide_version=run.aide_version, change_type=change_type,
            file_path=path, summary_string=summary,
            entry_type=entry_type_from_summary(summary),
        )
        d = detail.get(path)
        if d:
            if not rec.entry_type:
                rec.entry_type = d.get("_kind", "")
            changed = []
            for a in TYPED_ATTRS:
                if a in d:
                    o, nw = d[a]
                    setattr(rec, f"{a}_old", o)
                    setattr(rec, f"{a}_new", nw)
                    changed.append(a)
            for lbl in d.get("_raw", {}):
                norm = _NORM_LABEL.get(lbl.lower().replace(" ", ""))
                if norm is None and lbl not in changed:
                    changed.append(lbl.lower())
            rec.changed_attrs = ", ".join(dict.fromkeys(changed))
            rec.changed_attrs_raw = json.dumps(d.get("_raw", {}), ensure_ascii=False)
        return rec

    for ct, idx in (("Added", idx_added), ("Removed", idx_removed),
                    ("Changed", idx_changed)):
        for summary, path in parse_grouped_section(section_body(idx)):
            records.append(build_record(ct, summary, path))

    if not records and detail:
        for path in detail:
            records.append(build_record("Changed", "", path))

    got = {"Added": 0, "Removed": 0, "Changed": 0}
    for r in records:
        got[r.change_type] = got.get(r.change_type, 0) + 1
    for ct, n in (("Added", run.added), ("Removed", run.removed), ("Changed", run.changed)):
        if n and got.get(ct, 0) and got[ct] != n:
            issues.append(ParseIssue(
                source_log=src, run_index=run_idx, severity="warning",
                message=f"{ct} count mismatch: summary={n}, parsed={got[ct]}",
            ))
            run.parse_status = "partial"

    if not records and (run.added or run.removed or run.changed):
        issues.append(ParseIssue(
            source_log=src, run_index=run_idx, severity="error",
            message="Summary reports changes but no entries were parsed.",
            excerpt="\n".join(lines[:12]),
        ))
        run.parse_status = "error"

    return run, records


# ===========================================================================
# Host detection
# ===========================================================================

RE_CRON_SUBJECT = re.compile(r"Daily AIDE report for\s+(\S+)", re.I)
RE_HOSTNAME_LINE = re.compile(r"^(?:Hostname|host)\s*[:=]\s*(\S+)", re.I)


def detect_host(full_text: str, src_path: str) -> str:
    m = RE_CRON_SUBJECT.search(full_text)
    if m:
        return m.group(1)
    m = RE_HOSTNAME_LINE.search(full_text)
    if m:
        return m.group(1)
    base = src_path.rsplit("/", 1)[-1]
    fm = re.search(r"([A-Za-z0-9][A-Za-z0-9._-]*?)[._-]?aide", base, re.I)
    if fm and fm.group(1) and fm.group(1).lower() not in ("", "the"):
        return fm.group(1)
    return base


# ===========================================================================
# DFIR enrichment
# ===========================================================================

# (pattern, category, base_severity, mitre) — first match wins; ordered
# most-specific / highest-risk first.
DEFAULT_RULES = [
    (r"^/etc/ld\.so\.preload$|^/etc/ld\.so\.conf", "persistence", "High", "T1574.006"),
    (r"^/etc/(shadow|gshadow|passwd|sudoers)(/|$)|^/etc/sudoers\.d/", "credential", "High", "T1003,T1098"),
    (r"(^|/)\.ssh/|^/etc/ssh/.*key|^/root/\.ssh/", "credential", "High", "T1098.004,T1552.004"),
    (r"^/etc/pam\.d/|^/etc/security/|(^|/)pam_\w+\.so$", "credential", "High", "T1556"),
    (r"^/etc/cron|^/var/spool/cron|^/etc/at\b|^/etc/anacrontab", "persistence", "High", "T1053.003"),
    (r"^/etc/systemd/|^/lib/systemd/system/|^/usr/lib/systemd/system/|^/run/systemd/system/", "persistence", "High", "T1543.002"),
    (r"^/etc/init\.d/|^/etc/rc\d?\.d/|^/etc/init/|^/etc/rc\.local$", "persistence", "High", "T1037"),
    (r"(^|/)\.(bashrc|bash_profile|profile|zshrc|bash_logout)$|^/etc/profile|^/etc/bashrc$|^/etc/bash\.bashrc$", "persistence", "Medium", "T1546.004"),
    (r"^/boot/|^/lib/modules/|^/usr/lib/modules/|^/etc/modprobe\.d/|^/etc/modules", "kernel-boot", "High", "T1547.006"),
    (r"^/(bin|sbin)/|^/usr/(bin|sbin)/|^/usr/local/(bin|sbin)/", "binary", "High", "T1554"),
    (r"^/lib/|^/lib64/|^/usr/lib/|^/usr/lib64/|^/usr/local/lib/", "binary", "Medium", "T1574"),
    (r"^/var/www/|^/srv/www/|^/etc/nginx/|^/etc/apache2/|^/etc/httpd/", "web", "Medium", "T1505.003"),
    (r"^/var/log/", "log", "Low", "T1070"),
    (r"^/etc/", "config", "Medium", ""),
    (r"^/tmp/|^/var/tmp/|^/dev/shm/", "staging", "Medium", "T1036"),
    (r".*", "other", "Low", ""),
]

WRITABLE_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/")
CONTENT_ATTRS = ("size", "md5", "sha1", "sha256", "sha512", "rmd160", "tiger", "crc32")
SEV_RANK = {"Low": 1, "Medium": 2, "High": 3}
_COMPILED_RULES = [(re.compile(p), c, s, m) for (p, c, s, m) in DEFAULT_RULES]


def _perm_flags(old: str, new: str) -> List[str]:
    """Detect setuid/setgid additions and world-writable from perms."""
    flags = []
    if not new:
        return flags
    if re.fullmatch(r"[0-7]{3,5}", new.strip()):
        try:
            on = int(old.strip(), 8) if re.fullmatch(r"[0-7]{3,5}", (old or "").strip()) else 0
            nn = int(new.strip(), 8)
            if (nn & 0o4000) and not (on & 0o4000):
                flags.append("setuid_added")
            if (nn & 0o2000) and not (on & 0o2000):
                flags.append("setgid_added")
            if nn & 0o0002:
                flags.append("world_writable")
        except ValueError:
            pass
        return flags
    n = new.strip()
    o = (old or "").strip()
    if "s" in n[3:4] and "s" not in o[3:4]:
        flags.append("setuid_added")
    if len(n) > 6 and n[6] == "s" and not (len(o) > 6 and o[6] == "s"):
        flags.append("setgid_added")
    if len(n) >= 9 and n[8] == "w":
        flags.append("world_writable")
    return flags


def _parse_ts(s: str) -> Optional[_dt.datetime]:
    s = (s or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return _dt.datetime.strptime(s, fmt)
        except ValueError:
            continue
    m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", s)
    if m:
        try:
            return _dt.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    return None


def enrich(rec: ChangeRecord) -> ChangeRecord:
    for rgx, cat, sev, mitre in _COMPILED_RULES:
        if rgx.search(rec.file_path):
            rec.category = cat
            base_sev = sev
            rec.mitre = mitre
            break
    else:
        rec.category, base_sev, rec.mitre = "other", "Low", ""

    flags: List[str] = []
    attrs = set(a.strip() for a in rec.changed_attrs.split(",") if a.strip())

    content_changed = any(a in attrs for a in CONTENT_ATTRS)
    if content_changed and "mtime" not in attrs:
        flags.append("content_changed_mtime_static")
    if "ctime" in attrs and "mtime" not in attrs and not content_changed:
        flags.append("ctime_only")
    if rec.mtime_new and rec.ctime_new:
        try:
            mt = _parse_ts(rec.mtime_new)
            ct = _parse_ts(rec.ctime_new)
            if mt and ct and mt < ct - _dt.timedelta(days=1):
                flags.append("mtime_before_ctime")
        except Exception:
            pass

    flags += _perm_flags(rec.perm_old, rec.perm_new)

    if rec.change_type == "Added" and rec.file_path.startswith(WRITABLE_DIRS):
        flags.append("new_in_writable_path")
    if rec.change_type == "Added" and rec.entry_type == "file" \
            and rec.category in ("binary", "staging"):
        flags.append("new_executable_candidate")
    if rec.change_type == "Removed" and rec.category in ("log",):
        flags.append("log_removed")

    rec.flags = ", ".join(dict.fromkeys(flags))

    sev_rank = SEV_RANK[base_sev]
    bump = {"content_changed_mtime_static", "setuid_added", "setgid_added",
            "mtime_before_ctime", "new_executable_candidate"}
    if bump & set(flags):
        sev_rank = max(sev_rank, 3)
    elif {"world_writable", "new_in_writable_path", "ctime_only", "log_removed"} & set(flags):
        sev_rank = max(sev_rank, 2)
    rec.severity = {1: "Low", 2: "Medium", 3: "High"}[sev_rank]
    return rec


# ===========================================================================
# JSON-format reports (best-effort, secondary)
# ===========================================================================

def parse_json_report(run_text: str, src: str, sha: str,
                      issues: List[ParseIssue]) -> Tuple[List[RunResult], List[ChangeRecord]]:
    issues.append(ParseIssue(
        source_log=src, run_index=0, severity="warning",
        message=("JSON-format AIDE report detected; parsed best-effort. "
                 "Re-run AIDE with report_format=plain for full fidelity."),
    ))
    try:
        data = json.loads(run_text)
    except json.JSONDecodeError as e:
        issues.append(ParseIssue(source_log=src, severity="error",
                                 message=f"JSON decode failed: {e}"))
        return [], []

    objs = data if isinstance(data, list) else [data]
    runs, recs = [], []
    for idx, obj in enumerate(objs):
        if not isinstance(obj, dict):
            continue
        run = RunResult(source_log=src, source_sha256=sha, run_index=idx,
                        report_format="json")
        run.aide_version = str(obj.get("aide") or obj.get("version") or "")
        run.run_start = str(obj.get("start_time") or obj.get("start") or "")
        run.run_end = str(obj.get("end_time") or obj.get("end") or "")
        summ = obj.get("summary", {}) if isinstance(obj.get("summary"), dict) else {}
        run.added = _to_int(str(summ.get("added", obj.get("added_entries", 0))))
        run.removed = _to_int(str(summ.get("removed", obj.get("removed_entries", 0))))
        run.changed = _to_int(str(summ.get("changed", obj.get("changed_entries", 0))))
        run.total_entries = str(summ.get("total", obj.get("total_entries", "")))
        for ct_key, ct in (("added", "Added"), ("removed", "Removed"), ("changed", "Changed")):
            section = obj.get(ct_key) or obj.get(f"{ct_key}_entries")
            if isinstance(section, list):
                for ent in section:
                    path = (ent.get("name") or ent.get("path")) if isinstance(ent, dict) else str(ent)
                    rec = ChangeRecord(source_log=src, source_sha256=sha,
                                       run_index=idx, change_type=ct,
                                       aide_version=run.aide_version,
                                       run_start=run.run_start,
                                       file_path=path or "")
                    if isinstance(ent, dict):
                        rec.changed_attrs_raw = json.dumps(ent, ensure_ascii=False)
                    recs.append(rec)
        runs.append(run)
    return runs, recs


def looks_like_aide(text: str) -> bool:
    """Cheap sniff so non-AIDE files in the evidence are skipped."""
    head = text[:8192]
    return (
        "AIDE" in head
        or "Start timestamp:" in head
        or "Detailed information about changes" in head
        or '"aide"' in head
    )


def parse_file(path: Path, issues: List[ParseIssue]) -> Tuple[List[RunResult], List[ChangeRecord]]:
    """Read + parse one AIDE log file (plain or JSON), returning runs + enriched
    change records. Reuses the suite's compression-aware reader / hasher."""
    try:
        sha = sha256_file(path)
        with open_text(path) as fh:
            text = fh.read()
    except (OSError, EOFError, Exception) as e:  # never abort the whole parser
        issues.append(ParseIssue(source_log=str(path), severity="error",
                                 message=f"Could not read file: {e}"))
        return [], []

    if not looks_like_aide(text):
        return [], []   # not an AIDE report — skip quietly

    host = detect_host(text, str(path))
    all_runs: List[RunResult] = []
    all_recs: List[ChangeRecord] = []

    for run_idx, run_text in segment_runs(text):
        stripped = run_text.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            jruns, jrecs = parse_json_report(run_text, str(path), sha, issues)
            for r in jruns:
                r.host = host
            for rc in jrecs:
                rc.host = host
                enrich(rc)
            all_runs += jruns
            all_recs += jrecs
            continue

        try:
            run, recs = parse_plain_run(run_idx, run_text, str(path), sha, issues)
        except Exception as e:  # never let one bad run kill the job
            issues.append(ParseIssue(
                source_log=str(path), run_index=run_idx, severity="error",
                message=f"Unhandled parse error: {type(e).__name__}: {e}",
                excerpt="\n".join(run_text.splitlines()[:10]),
            ))
            continue

        run.host = host
        for rc in recs:
            rc.host = host
            enrich(rc)
        run.n_sensitive = sum(1 for r in recs if r.category not in ("other", "config", "log"))
        run.n_high = sum(1 for r in recs if r.severity == "High")
        run.n_medium = sum(1 for r in recs if r.severity == "Medium")
        all_runs.append(run)
        all_recs += recs

    return all_runs, all_recs


# ===========================================================================
# Suite adapter
# ===========================================================================

# AIDE base severity -> suite severity.
_SEV_MAP = {"High": SEV_HIGH, "Medium": SEV_MEDIUM, "Low": SEV_LOW}
# High-signal flags that escalate a HIGH change to CRITICAL.
_CRITICAL_FLAGS = {"setuid_added", "setgid_added",
                   "content_changed_mtime_static", "mtime_before_ctime"}

CHANGE_COLUMNS = (
    ["source_log", "host", "run_start", "run_index", "aide_version",
     "change_type", "entry_type", "file_path", "category", "severity",
     "mitre", "flags", "changed_attrs"]
    + [f"{a}_{w}" for a in ("size", "perm", "uid", "gid", "inode", "linkcount",
                            "mtime", "ctime", "atime", "sha256", "sha512", "md5",
                            "selinux") for w in ("old", "new")]
    + ["summary_string", "changed_attrs_raw", "source_sha256"]
)
RUN_COLUMNS = ["source_log", "host", "run_index", "aide_version", "report_format",
               "run_start", "run_end", "run_seconds", "total_entries",
               "added", "removed", "changed", "n_sensitive", "n_high",
               "n_medium", "parse_status", "note", "source_sha256"]


class AideParser(BaseParser):
    name = "aide"

    def run(self) -> None:
        paths = self._find_logs()
        if not paths:
            return

        issues: List[ParseIssue] = []
        all_runs: List[RunResult] = []
        all_recs: List[ChangeRecord] = []
        for p in paths:
            self.note_file(p)
            runs, recs = parse_file(p, issues)
            all_runs += runs
            all_recs += recs

        for rec in all_recs:
            self._emit(rec)

        self._write_csvs(all_recs, all_runs, issues)

    # ------------------------------------------------------------------
    def _find_logs(self) -> List[Path]:
        seen: set = set()
        out: List[Path] = []
        candidates = list(self.finder.find_log_family("aide.log"))
        candidates += self.finder.find_by_glob([
            "**/var/log/aide/**/*",
            "**/var/log/aide.log*",
        ])
        for p in candidates:
            try:
                if p.is_file() and p not in seen:
                    seen.add(p)
                    out.append(p)
            except OSError:
                continue
        return out

    # ------------------------------------------------------------------
    def _emit(self, rec: ChangeRecord) -> None:
        sev = _SEV_MAP.get(rec.severity, SEV_LOW)
        flags = {f.strip() for f in rec.flags.split(",") if f.strip()}
        if sev == SEV_HIGH and (flags & _CRITICAL_FLAGS):
            sev = SEV_CRITICAL

        ts = _parse_ts(rec.run_start)

        # Every change -> a timeline event.
        desc = f"{rec.change_type} {rec.entry_type or 'entry'}: {rec.file_path}"
        if rec.changed_attrs:
            desc += f" [{rec.changed_attrs}]"
        self.emit_event(
            timestamp=ts or _dt.datetime.now(_dt.timezone.utc),
            source="aide",
            event_type=f"aide_{rec.change_type.lower()}",
            description=desc[:500],
            host=rec.host or None,
            metadata={
                "category": rec.category, "mitre": rec.mitre,
                "flags": rec.flags, "attrs": rec.changed_attrs,
                "change_type": rec.change_type, "severity": rec.severity,
            },
            raw=rec.summary_string or None,
        )

        # Medium+ changes -> a finding (Low changes stay timeline-only to
        # avoid flooding routine log/cache churn into the findings list).
        if SEV_ORDER.get(sev, 0) < SEV_ORDER[SEV_MEDIUM]:
            return

        evidence = []
        if rec.changed_attrs:
            evidence.append(f"changed: {rec.changed_attrs}")
        for a in ("perm", "uid", "gid", "sha256", "mtime", "ctime"):
            o = getattr(rec, f"{a}_old", "")
            n = getattr(rec, f"{a}_new", "")
            if o or n:
                evidence.append(f"{a}: {o or '-'} -> {n or '-'}")

        title = f"AIDE {rec.change_type}: {rec.file_path}"
        description = (
            f"AIDE detected a {rec.change_type.lower()} "
            f"{rec.entry_type or 'entry'} at {rec.file_path}"
            + (f" (flags: {rec.flags})" if rec.flags else "")
            + (f" [MITRE {rec.mitre}]" if rec.mitre else "")
        )
        self.emit_finding(
            severity=sev,
            category=rec.category or "file_integrity",
            title=title[:200],
            description=description,
            artifact=rec.source_log,
            evidence=evidence[:8],
            timestamp=ts,
            metadata={
                "host": rec.host, "mitre": rec.mitre, "flags": rec.flags,
                "change_type": rec.change_type, "entry_type": rec.entry_type,
                "changed_attrs": rec.changed_attrs, "aide_severity": rec.severity,
            },
        )

    # ------------------------------------------------------------------
    def _write_csvs(self, recs: List[ChangeRecord], runs: List[RunResult],
                    issues: List[ParseIssue]) -> None:
        def rows(items, cols):
            out = []
            for it in items:
                d = _asdict(it)
                out.append({c: neutralize_formula(d.get(c, "")) for c in cols})
            return out

        if recs:
            self.write_csv("aide_changes.csv", rows(recs, CHANGE_COLUMNS), CHANGE_COLUMNS)
        if runs:
            self.write_csv("aide_run_summary.csv", rows(runs, RUN_COLUMNS), RUN_COLUMNS)
        if issues:
            icols = ["source_log", "run_index", "severity", "message", "excerpt"]
            self.write_csv("aide_parse_issues.csv", rows(issues, icols), icols)
