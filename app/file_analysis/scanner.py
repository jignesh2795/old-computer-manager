"""Safe, read-only directory scanner.

Scans directories without following symlinks, without loading entire trees
into memory, and without modifying any file metadata.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from app.file_analysis.exclusions import is_excluded_entry
from app.file_analysis.models import FileRecord, ScanStats


def scan_directory(
    root: str | Path,
    *,
    max_files: int | None = None,
) -> tuple[list[FileRecord], ScanStats]:
    """Recursively scan a directory for files.

    Returns a tuple of (files, stats). The scan:
    - Never follows symlinks
    - Skips excluded paths
    - Handles permission errors gracefully
    - Does not modify file access/mtime timestamps
    - Does not open file contents

    Args:
        root: Directory to scan. Must be validated first.
        max_files: Optional limit on number of files to collect.

    Returns:
        Tuple of (list of FileRecord, ScanStats).
    """
    root_path = Path(root).resolve()
    stats = ScanStats()
    files: list[FileRecord] = []
    start = time.monotonic()

    _scan_recursive(root_path, root_path, files, stats, max_files)

    elapsed = time.monotonic() - start
    stats.roots_scanned = 1
    stats.elapsed_seconds = round(elapsed, 3)
    return files, stats


def _scan_recursive(
    current: Path,
    scan_root: Path,
    files: list[FileRecord],
    stats: ScanStats,
    max_files: int | None,
) -> None:
    """Recursively scan a directory. Internal helper."""
    if max_files is not None and len(files) >= max_files:
        return

    try:
        with os.scandir(current) as entries:
            for entry in entries:
                if max_files is not None and len(files) >= max_files:
                    return

                name = entry.name
                entry_path = current / name

                # Check exclusion before doing anything else
                try:
                    is_symlink = entry.is_symlink()
                except OSError:
                    is_symlink = False

                try:
                    is_dir = entry.is_dir()
                except OSError:
                    is_dir = False

                excluded, reason = is_excluded_entry(
                    name, entry_path, is_symlink, is_dir, scan_root
                )
                if excluded:
                    if reason == "symlink":
                        stats.symlinks_skipped += 1
                    else:
                        stats.excluded_items += 1
                    continue

                # -- Directory ---------------------------------------------
                if is_dir:
                    stats.directories_examined += 1
                    _scan_recursive(entry_path, scan_root, files, stats, max_files)
                    continue

                # -- File --------------------------------------------------
                if entry.is_file():
                    try:
                        stat = entry.stat(follow_symlinks=False)
                    except (OSError, PermissionError) as exc:
                        stats.inaccessible_items += 1
                        stats.errors.append(f"{entry_path}: {exc}")
                        continue

                    ext = _get_extension(name)
                    record = FileRecord(
                        path=str(entry_path),
                        size_bytes=stat.st_size,
                        modified_time=stat.st_mtime,
                        created_time=getattr(stat, "st_birthtime", None),
                        extension=ext,
                        filename=name,
                        parent_directory=str(current),
                        scan_root=str(scan_root),
                    )
                    files.append(record)
                    stats.files_examined += 1
                    stats.bytes_examined += stat.st_size

    except PermissionError as exc:
        stats.inaccessible_items += 1
        stats.errors.append(f"{current}: {exc}")
    except OSError as exc:
        stats.errors.append(f"{current}: {exc}")


def _get_extension(filename: str) -> str:
    """Extract lowercase extension including dot, or '' if none."""
    _, ext = os.path.splitext(filename)
    return ext.lower()
