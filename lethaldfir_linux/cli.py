"""
lethaldfir_linux.cli
====================

Command-line orchestrator. Loads evidence, dispatches parsers, writes
reports. Tuned for both native Linux and Windows Subsystem for Linux:

  * Windows-style paths (``C:\\Cases\\evidence``, ``D:/IR/wtmp``) are
    auto-translated to ``/mnt/c/...`` / ``/mnt/d/...`` mount paths.
  * ANSI colour is auto-disabled when stdout is not a TTY, when
    ``NO_COLOR`` is set, or when ``--no-color`` is passed.
  * Distro-aware install hints are emitted when optional system tools
    are missing.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Parsers run first, sequentially, in this order — they populate shared
# Case state the others / the reports rely on (host_info, the live account
# dataset). Every other parser is independent and is run in parallel.
_SEQUENTIAL_FIRST = ("host_metadata", "passwd_shadow_group", "passwd_backup")

from . import __version__, __brand__
from .core import Case, EvidenceFinder
from .parsers import ALL_PARSERS, PARSERS_BY_NAME


# ---------------------------------------------------------------------------
# WSL / environment helpers
# ---------------------------------------------------------------------------
def is_wsl() -> bool:
    """Return True if running under Windows Subsystem for Linux."""
    if sys.platform != "linux":
        return False
    try:
        with open("/proc/version", "r", errors="replace") as f:
            ver = f.read().lower()
        return "microsoft" in ver or "wsl" in ver
    except OSError:
        return False


def detect_distro() -> str:
    """Best-effort distro detection from /etc/os-release."""
    try:
        with open("/etc/os-release", "r", errors="replace") as f:
            for line in f:
                if line.startswith("ID="):
                    return line.split("=", 1)[1].strip().strip('"').lower()
    except OSError:
        pass
    return "unknown"


_WIN_PATH_RE = re.compile(r"^([A-Za-z]):[\\/](.*)$")
_WIN_DRIVE_RE = re.compile(r"^([A-Za-z]):[\\/]?$")


def translate_windows_path(path_str: str) -> str:
    """Translate a Windows-style path to a WSL ``/mnt/<drive>/...`` path.

    Pass-through for anything that doesn't look like a Windows path.
    Examples
    --------
        C:\\Cases\\evidence  ->  /mnt/c/Cases/evidence
        D:/IR/wtmp           ->  /mnt/d/IR/wtmp
        /mnt/c/Cases         ->  /mnt/c/Cases   (unchanged)
    """
    if not path_str:
        return path_str
    m = _WIN_PATH_RE.match(path_str)
    if m:
        drive = m.group(1).lower()
        rest = m.group(2).replace("\\", "/")
        return f"/mnt/{drive}/{rest}"
    m = _WIN_DRIVE_RE.match(path_str)
    if m:
        return f"/mnt/{m.group(1).lower()}"
    return path_str


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = r"""
   __     ___   __        __    ___  ___ __ ___
  / /  ___| |_/ /_  __ _ / /   / _ \/ __/ // _ \
 / /__/ -_) __/ _ \/ _` / /   / // / _// // , _/
/____/\__/\__/_//_/\__,_/_/  /____/_/ /_//_/|_|
       Linux Forensics  -  Offline Triage
"""


def _print_banner(stream=sys.stderr) -> None:
    stream.write(BANNER + "\n")
    stream.write(f"  {__brand__}  v{__version__}\n")
    if is_wsl():
        stream.write(f"  Running under WSL  (distro: {detect_distro()})\n")
    stream.write("\n")
    stream.flush()


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lethaldfir-linux",
        description=(
            "LethalDFIR Linux Forensics — offline triage tool for Linux "
            "evidence collected via forensic collector ZIPs, mounted "
            "disk images, or extracted directory trees. Produces a JSON "
            "evidence bundle, super-timeline CSV, findings CSV, branded "
            "HTML investigation report, and (optionally) a branded XLSX "
            "workbook with binary login analysis. Runs from native Linux "
            "or WSL; Windows-style paths auto-translate to /mnt/<drive>/."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples (Linux native):\n"
            "  lethaldfir-linux -i Collection-host.zip -o ./out\n"
            "  lethaldfir-linux -i /mnt/image -o ./out --case-name web01\n"
            "  lethaldfir-linux -i ./extracted/ -o ./out "
            "--parsers auth_log,wtmp_btmp,ssh\n"
            "\n"
            "Examples (WSL — Windows paths auto-translated):\n"
            "  lethaldfir-linux -i 'C:\\\\Cases\\\\IR\\\\Collection.zip' -o ./out\n"
            "  lethaldfir-linux -i D:/Cases/IR/evidence -o /mnt/c/Cases/IR/out\n"
            "  lethaldfir-linux -i /mnt/c/Cases/wtmp --case-name web01 --no-color\n"
        ),
    )

    p.add_argument(
        "-i", "--input", required=True,
        help="Path to evidence: directory, ZIP, tar, tar.gz, or single file. "
             "Windows-style paths (C:\\..., D:/...) accepted on WSL.",
    )
    p.add_argument(
        "-o", "--output", required=True,
        help="Output directory (created if missing).",
    )
    p.add_argument(
        "--case-name", default=None,
        help="Case name (default: derived from input filename).",
    )
    p.add_argument(
        "--parsers", default=None,
        help=(
            "Comma-separated list of parsers to run (default: all). "
            "Available: " + ", ".join(sorted(PARSERS_BY_NAME))
        ),
    )
    p.add_argument(
        "--list-parsers", action="store_true",
        help="List available parsers and exit.",
    )
    p.add_argument(
        "--jobs", "-j", type=int, default=0, metavar="N",
        help="Parser worker threads (default: auto from CPU count). "
             "Use 1 for fully sequential, deterministic execution.",
    )
    p.add_argument(
        "--no-html", action="store_true",
        help="Skip HTML report generation.",
    )
    p.add_argument(
        "--no-xlsx", action="store_true",
        help="Skip XLSX workbook generation.",
    )
    p.add_argument(
        "--no-timeline", action="store_true",
        help="Skip super-timeline CSV generation.",
    )
    p.add_argument(
        "--no-banner", action="store_true",
        help="Suppress banner.",
    )
    p.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour output (useful when piping to a file or "
             "running from cmd.exe / PowerShell with redirection).",
    )
    p.add_argument(
        "--quiet", "-q", action="store_true",
        help="Reduce console output.",
    )
    p.add_argument(
        "--version", action="version",
        version=f"{__brand__} v{__version__}",
    )
    return p


def _select_parsers(spec: str | None):
    if not spec:
        return list(ALL_PARSERS)
    chosen = []
    unknown = []
    for raw in spec.split(","):
        name = raw.strip()
        if not name:
            continue
        if name in PARSERS_BY_NAME:
            chosen.append(PARSERS_BY_NAME[name])
        else:
            unknown.append(name)
    if unknown:
        raise SystemExit(
            f"[!] Unknown parser(s): {', '.join(unknown)}\n"
            f"    Available: {', '.join(sorted(PARSERS_BY_NAME))}"
        )
    return chosen


def _derive_case_name(input_path: Path) -> str:
    name = input_path.name or "case"
    for ext in (".tar.gz", ".tgz", ".zip", ".tar"):
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
            break
    return name or "case"


def run(argv: list[str] | None = None) -> int:
    # Pre-scan for --list-parsers so users don't have to also supply -i/-o.
    pre = argv if argv is not None else sys.argv[1:]
    if "--list-parsers" in pre:
        print("Available parsers:")
        for name in sorted(PARSERS_BY_NAME):
            print(f"  - {name}")
        return 0

    args = build_argparser().parse_args(argv)

    if not args.no_banner and not args.quiet:
        _print_banner()

    if args.list_parsers:
        print("Available parsers:")
        for name in sorted(PARSERS_BY_NAME):
            print(f"  - {name}")
        return 0

    # ------------------------------------------------------------------
    # Translate Windows-style paths (C:\..., D:/...) to WSL paths.
    # Pass-through for Linux-native paths.
    # ------------------------------------------------------------------
    raw_in, raw_out = args.input, args.output
    args.input  = translate_windows_path(args.input)
    args.output = translate_windows_path(args.output)
    if is_wsl() and not args.quiet:
        if args.input != raw_in:
            print(f"[+] Translated Windows path: {raw_in!r} -> {args.input!r}")
        if args.output != raw_out:
            print(f"[+] Translated Windows path: {raw_out!r} -> {args.output!r}")

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        print(f"[!] Input not found: {input_path}", file=sys.stderr)
        if is_wsl() and re.match(r"^[A-Za-z]:[\\/]", raw_in or ""):
            print("    Hint: under WSL, drive C: is mounted at /mnt/c. "
                  "Confirm with: ls /mnt/c/<your-folder>", file=sys.stderr)
        return 2

    out_dir = Path(args.output).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    case_name = args.case_name or _derive_case_name(input_path)
    parsers_to_run = _select_parsers(args.parsers)

    if not args.quiet:
        print(f"[+] Case        : {case_name}")
        print(f"[+] Input       : {input_path}")
        print(f"[+] Output      : {out_dir}")
        print(f"[+] Parsers     : {len(parsers_to_run)}")
        print()

    t_start = time.time()
    with EvidenceFinder(input_path) as finder:
        if not args.quiet:
            print(f"[+] Evidence root resolved to: {finder.root}")
            print()

        case = Case(evidence_root=finder.root, case_name=case_name,
                    output_dir=out_dir)

        def _run_one(parser_cls):
            """Run + finalize one parser. Returns (name, seconds, exc|None).
            Safe to call from worker threads: each parser is its own object,
            and the shared Case only takes list-appends / per-parser-keyed
            dict writes, which are atomic under the GIL."""
            parser = parser_cls(case=case, finder=finder)
            t0 = time.time()
            try:
                parser.run()
                parser.finalize()
            except Exception as exc:  # noqa: BLE001
                case.record_stats(
                    parser.name,
                    errors=[f"FATAL: {exc}", traceback.format_exc()],
                )
                return (parser.name, time.time() - t0, exc)
            return (parser.name, time.time() - t0, None)

        def _report(result):
            name, dt, exc = result
            if args.quiet:
                return
            if exc is not None:
                print(f"  [!] {name:24s}  FAILED: {exc}  ({dt:.2f}s)")
                return
            stats = case.stats.get(name, {})
            print(
                f"  [+] {name:24s}  "
                f"files={stats.get('files',0):<5d} "
                f"events={stats.get('events',0):<6d} "
                f"findings={stats.get('findings',0):<4d} "
                f"({dt:.2f}s)"
            )

        # Phase 1: dependency-ordered parsers, sequential.
        prelude = [p for p in parsers_to_run if p.name in _SEQUENTIAL_FIRST]
        rest = [p for p in parsers_to_run if p.name not in _SEQUENTIAL_FIRST]
        for parser_cls in prelude:
            _report(_run_one(parser_cls))

        # Phase 2: independent parsers in parallel (I/O- and subprocess-bound
        # work — file reads, journalctl — overlaps well under threads). Use
        # --jobs 1 for fully deterministic sequential execution.
        if args.jobs and args.jobs > 0:
            workers = args.jobs
        else:
            workers = min(len(rest) or 1, (os.cpu_count() or 4))
        if workers <= 1 or len(rest) <= 1:
            for parser_cls in rest:
                _report(_run_one(parser_cls))
        else:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                for fut in as_completed([ex.submit(_run_one, p) for p in rest]):
                    _report(fut.result())

        # ----------------------------------------------------------------
        # Reports
        # ----------------------------------------------------------------
        if not args.quiet:
            print()
            print("[+] Writing reports...")

        from .reports import write_json, write_findings_csv
        from .reports import write_timeline_csv, write_html
        from .reports import write_user_accounts_csv

        out_dir.mkdir(parents=True, exist_ok=True)
        produced: dict[str, Path] = {}

        produced["json"]     = write_json(case, out_dir / "case.json")
        produced["findings"] = write_findings_csv(case, out_dir / "findings.csv")
        produced["users"]    = write_user_accounts_csv(
            case, out_dir / "user_accounts.csv")

        if not args.no_timeline:
            produced["timeline"] = write_timeline_csv(case, out_dir / "timeline.csv")
        if not args.no_html:
            produced["html"] = write_html(case, out_dir / "report.html")

        # XLSX is optional - requires openpyxl. We import lazily and
        # gracefully degrade if it's missing.
        if not args.no_xlsx:
            try:
                from .reports.xlsx_report import write_xlsx, HAS_OPENPYXL
                if HAS_OPENPYXL:
                    produced["xlsx"] = write_xlsx(
                        case, out_dir / f"{case_name}_LethalDFIR_Report.xlsx"
                    )
                elif not args.quiet:
                    print("    - xlsx      SKIPPED (openpyxl not installed; "
                          "run: pip install openpyxl)")
            except Exception as exc:  # noqa: BLE001
                if not args.quiet:
                    print(f"    - xlsx      FAILED: {exc}")

        if not args.quiet:
            for label, p in produced.items():
                print(f"    - {label:9s} {p}")

            # List per-parser CSV files if any were written
            csv_dir = out_dir / "csv"
            if csv_dir.exists():
                csv_files = sorted(csv_dir.glob("*.csv"))
                if csv_files:
                    print(f"\n    Per-parser CSV output ({len(csv_files)} files):")
                    for cf in csv_files:
                        size = cf.stat().st_size
                        print(f"    - {cf.name} ({size:,} bytes)")

    dt = time.time() - t_start
    counts = case.severity_counts()
    if not args.quiet:
        print()
        print(f"[+] Done in {dt:.2f}s")
        print(f"    findings: "
              f"CRITICAL={counts.get('CRITICAL',0)} "
              f"HIGH={counts.get('HIGH',0)} "
              f"MEDIUM={counts.get('MEDIUM',0)} "
              f"LOW={counts.get('LOW',0)} "
              f"INFO={counts.get('INFO',0)}")
        print(f"    events  : {len(case.events)}")
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
