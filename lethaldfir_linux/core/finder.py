"""
core.finder
===========

Locate Linux forensic artifacts inside an input source.

Supported input layouts
-----------------------
1. **Mounted disk image / extracted directory tree** - root of file system.
2. **Forensic collector ZIP** (``Collector_*.zip``) - extracted
   on demand to a working directory.
3. **Generic directory** of collected files where Linux paths may appear
   under arbitrary prefixes (``./<host>/<original_path>``,
   ``./uploads/auto/...``, etc.). The finder walks recursively and
   matches by suffix.
4. **tar / tar.gz** archives - extracted on demand.

The finder is intentionally permissive: it returns *every* matching path
(not just the canonical one) so parsers can analyse e.g. all rotated log
files and every user's history file.
"""

from __future__ import annotations

import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable


class EvidenceFinder:
    """Index files in the evidence tree and provide lookup helpers."""

    def __init__(self, source: Path) -> None:
        self.source_arg: Path = source
        self._tempdir: Path | None = None
        self.root: Path = self._prepare_root(source)
        self._index: list[Path] = self._build_index(self.root)

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def _prepare_root(self, source: Path) -> Path:
        if source.is_dir():
            return source
        if not source.exists():
            raise FileNotFoundError(source)

        suffix = "".join(source.suffixes).lower()
        self._tempdir = Path(tempfile.mkdtemp(prefix="lethaldfir_"))

        if zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as zf:
                zf.extractall(self._tempdir)
        elif suffix.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")):
            with tarfile.open(source) as tf:
                tf.extractall(self._tempdir)
        else:
            raise ValueError(f"Unsupported source type: {source}")

        return self._tempdir

    def _build_index(self, root: Path) -> list[Path]:
        index: list[Path] = []
        for p in root.rglob("*"):
            try:
                if p.is_file() or p.is_symlink():
                    index.append(p)
            except OSError:
                continue
        return index

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------
    def find_by_suffix(self, suffixes: Iterable[str]) -> list[Path]:
        """Return files whose POSIX path *ends with* any of ``suffixes``.

        Example: ``find_by_suffix(["/var/log/auth.log"])`` will match
        ``/mnt/img/var/log/auth.log`` and any rotated equivalent.
        """
        wanted = [s.lstrip("/").lower() for s in suffixes]
        out: list[Path] = []
        for p in self._index:
            posix = p.as_posix().lower()
            for w in wanted:
                if posix.endswith(w) or f"/{w}" in posix:
                    out.append(p)
                    break
        return out

    def find_by_glob(self, patterns: Iterable[str]) -> list[Path]:
        """Return files matching any rglob pattern."""
        seen: set[Path] = set()
        out: list[Path] = []
        for pat in patterns:
            for p in self.root.rglob(pat):
                if p.is_file() and p not in seen:
                    seen.add(p)
                    out.append(p)
        return out

    def find_log_family(self, base: str) -> list[Path]:
        """Find ``base`` plus rotated/compressed variants.

        e.g. ``find_log_family("auth.log")`` matches ``auth.log``,
        ``auth.log.1``, ``auth.log.2.gz``, ``auth.log-20250901``.
        """
        out: list[Path] = []
        base_l = base.lower()
        for p in self._index:
            name = p.name.lower()
            if name == base_l:
                out.append(p)
            elif name.startswith(base_l + ".") or name.startswith(base_l + "-"):
                out.append(p)
        return out

    def all_files(self) -> list[Path]:
        return list(self._index)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def cleanup(self) -> None:
        if self._tempdir and self._tempdir.exists():
            shutil.rmtree(self._tempdir, ignore_errors=True)

    def __enter__(self) -> "EvidenceFinder":
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()
