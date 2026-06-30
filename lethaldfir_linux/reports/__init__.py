"""
LethalDFIR Linux Forensics — report generators.

Read from a populated Case object and produce on-disk artifacts:

  * JSON evidence bundle  -> json_report.write_json
  * Findings CSV          -> csv_report.write_findings_csv
  * Super-timeline CSV    -> timeline_csv.write_timeline_csv
  * HTML investigation    -> html_report.write_html
"""

from .json_report import write_json
from .csv_report import write_findings_csv
from .timeline_csv import write_timeline_csv
from .html_report import write_html
from .user_accounts_csv import write_user_accounts_csv

# XLSX is optional - openpyxl may not be installed.
try:
    from .xlsx_report import write_xlsx, HAS_OPENPYXL
except ImportError:                                                # pragma: no cover
    HAS_OPENPYXL = False
    def write_xlsx(case, path):
        raise RuntimeError("openpyxl is not installed. "
                           "Install: pip install openpyxl")


def write_all(case, out_dir):
    """Write every standard report into ``out_dir``."""
    from pathlib import Path
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "json":          out_dir / "case.json",
        "findings":      out_dir / "findings.csv",
        "timeline":      out_dir / "timeline.csv",
        "user_accounts": out_dir / "user_accounts.csv",
        "html":          out_dir / "report.html",
    }
    write_json(case, paths["json"])
    write_findings_csv(case, paths["findings"])
    write_timeline_csv(case, paths["timeline"])
    write_user_accounts_csv(case, paths["user_accounts"])
    write_html(case, paths["html"])
    if HAS_OPENPYXL:
        paths["xlsx"] = out_dir / f"{case.case_name}_LethalDFIR_Report.xlsx"
        write_xlsx(case, paths["xlsx"])
    return paths


__all__ = [
    "write_json",
    "write_findings_csv",
    "write_timeline_csv",
    "write_user_accounts_csv",
    "write_html",
    "write_xlsx",
    "write_all",
    "HAS_OPENPYXL",
]
