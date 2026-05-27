"""
reports.csv_report
==================

Writes ``findings.csv`` — one row per Finding, sorted by severity then
category. Suitable for direct import into Excel / Splunk / pandas.
"""

from __future__ import annotations

import csv
from pathlib import Path


FIELDS = [
    "severity",
    "category",
    "title",
    "description",
    "artifact",
    "timestamp",
    "evidence",
    "metadata",
]


def write_findings_csv(case, path) -> Path:
    path = Path(path)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        for f in case.findings_sorted():
            ts = f.timestamp.isoformat() if f.timestamp else ""
            writer.writerow({
                "severity":    f.severity,
                "category":    f.category,
                "title":       f.title,
                "description": f.description,
                "artifact":    f.artifact,
                "timestamp":   ts,
                "evidence":    " | ".join(f.evidence) if f.evidence else "",
                "metadata":    "; ".join(f"{k}={v}" for k, v in f.metadata.items()),
            })
    return path
