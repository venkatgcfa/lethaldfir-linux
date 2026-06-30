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

import os
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable


def _within(base: Path, target: Path) -> bool:
    """True if ``target`` is ``base`` itself or nested under it."""
    return target == base or base in target.parents


def _safe_zip_names(dest: Path, zf: "zipfile.ZipFile") -> tuple[list[str], list[str]]:
    """Partition zip member names into (safe, unsafe) by whether they extract
    inside ``dest``. Defends against Zip-Slip (``../`` and absolute members)."""
    dest_r = dest.resolve()
    safe: list[str] = []
    unsafe: list[str] = []
    for name in zf.namelist():
        # ``dest / name`` collapses an absolute member onto itself; resolve()
        # then normalizes ``..`` so containment can be verified.
        if _within(dest_r, (dest / name).resolve()):
            safe.append(name)
        else:
            unsafe.append(name)
    return safe, unsafe


def _safe_tar_members(dest: Path, tf: "tarfile.TarFile") -> tuple[list, int]:
    """Return (safe members, skipped count). Rejects tar members that would
    extract outside ``dest`` (path traversal), symlink/hardlink members whose
    target escapes ``dest``, and device/FIFO nodes."""
    dest_r = dest.resolve()
    members: list = []
    skipped = 0
    for m in tf.getmembers():
        target = (dest / m.name).resolve()
        if not _within(dest_r, target):
            skipped += 1
            continue
        if m.issym() or m.islnk():
            link = (target.parent / m.linkname).resolve()
            if not _within(dest_r, link):
                skipped += 1
                continue
        elif m.isdev():            # char/block/FIFO — never materialize
            skipped += 1
            continue
        members.append(m)
    return members, skipped


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

        # On ANY failure (unsupported type, corrupt archive, traversal guard)
        # __init__ raises before the context manager is entered, so clean up
        # the just-created temp dir here instead of leaking it under /tmp.
        try:
            if zipfile.is_zipfile(source):
                with zipfile.ZipFile(source) as zf:
                    safe, unsafe = _safe_zip_names(self._tempdir, zf)
                    if unsafe:
                        print(
                            f"[!] Skipped {len(unsafe)} zip member(s) with unsafe "
                            f"paths (path traversal), e.g. {unsafe[0]!r}",
                            file=sys.stderr,
                        )
                    zf.extractall(self._tempdir, members=safe)
            elif suffix.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")):
                with tarfile.open(source) as tf:
                    members, skipped = _safe_tar_members(self._tempdir, tf)
                    if skipped:
                        print(
                            f"[!] Skipped {skipped} tar member(s) with unsafe paths "
                            f"or device/link types (path traversal)",
                            file=sys.stderr,
                        )
                    tf.extractall(self._tempdir, members=members)
            else:
                raise ValueError(f"Unsupported source type: {source}")
        except BaseException:
            shutil.rmtree(self._tempdir, ignore_errors=True)
            self._tempdir = None
            raise

        return self._tempdir

    def _build_index(self, root: Path) -> list[Path]:
        # os.walk(followlinks=False) so symlinked directories are never
        # descended (prevents reading the analyst host fs and symlink-loop
        # hangs). File symlinks are indexed ONLY when their target stays
        # within the evidence root — otherwise a collected/imaged absolute
        # symlink (e.g. /etc/passwd) would make parsers read the host's own
        # files instead of evidence.
        root_r = root.resolve()
        index: list[Path] = []
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(dirpath)
            for name in filenames:
                p = base / name
                try:
                    if p.is_symlink():
                        target = p.resolve()
                        if _within(root_r, target) and target.is_file():
                            index.append(p)
                    elif p.is_file():
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
