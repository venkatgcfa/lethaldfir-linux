"""
reports.json_report
===================

Dumps the entire Case as a structured JSON evidence bundle. Suitable for
downstream tooling, custom dashboards, or ingestion into SIEM / lake
pipelines.
"""

from __future__ import annotations

from pathlib import Path


def write_json(case, path) -> Path:
    """Write the full case to ``path`` as pretty-printed JSON."""
    path = Path(path)
    case.write_json(path)
    return path
