"""Orchestrates file scanning and analysis.

Runs the scanner and all analysis modules against a validated root directory.
"""

from __future__ import annotations

from pathlib import Path

from app.file_analysis.analyzers import (
    aggregate_directory_sizes,
    detect_duplicates,
    find_large_files,
    find_recently_modified,
    group_by_extension,
)
from app.file_analysis.exclusions import validate_scan_root
from app.file_analysis.models import ScanResult, ScanStats
from app.file_analysis.scanner import scan_directory


def run_file_analysis(
    root: str | Path,
    *,
    large_top_n: int = 50,
    large_min_bytes: int = 100 * 1024 * 1024,
    dir_top_n: int = 30,
    recent_days: int = 7,
    dup_max_groups: int = 100,
) -> ScanResult:
    """Run a complete file analysis on a validated root directory.

    This is a read-only operation. Nothing is modified.

    Args:
        root: Directory to scan. Must exist and not be system-critical.
        large_top_n: Number of largest files to report.
        large_min_bytes: Minimum size for large-file inclusion.
        dir_top_n: Number of largest directories to report.
        recent_days: Days to look back for recently modified files.
        dup_max_groups: Maximum duplicate groups to report.

    Returns:
        ScanResult with all analysis outputs.
    """
    root_path = validate_scan_root(root)

    files, stats = scan_directory(root_path)

    large = find_large_files(files, top_n=large_top_n, min_bytes=large_min_bytes)
    dirs = aggregate_directory_sizes(files, top_n=dir_top_n)
    types = group_by_extension(files)
    recent = find_recently_modified(files, days=recent_days)
    dupes = detect_duplicates(files, max_groups=dup_max_groups)

    return ScanResult(
        scan_root=str(root_path),
        stats=stats,
        large_files=large,
        directory_sizes=dirs,
        file_type_groups=types,
        recently_modified=recent,
        duplicate_groups=dupes,
    )
