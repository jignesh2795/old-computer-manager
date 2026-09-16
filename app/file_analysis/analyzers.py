"""File analysis modules: large files, directory sizes, file types,
recently modified files, and duplicate detection.

All analysis is read-only and does not modify the filesystem.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from pathlib import Path

from app.file_analysis.models import (
    DirectorySizeResult,
    DuplicateGroup,
    FileRecord,
    FileTypeGroup,
    LargeFileResult,
)


# -- Constants (centralized) -----------------------------------------------

DEFAULT_LARGE_FILE_TOP_N = 50
DEFAULT_LARGE_FILE_MIN_BYTES = 100 * 1024 * 1024  # 100 MB

DEFAULT_DIR_SIZE_TOP_N = 30

DEFAULT_RECENT_DAYS = 7

# -- Large files -----------------------------------------------------------


def find_large_files(
    files: list[FileRecord],
    *,
    top_n: int = DEFAULT_LARGE_FILE_TOP_N,
    min_bytes: int = DEFAULT_LARGE_FILE_MIN_BYTES,
) -> list[LargeFileResult]:
    """Return the top-N largest files above min_bytes.

    Args:
        files: List of FileRecord from scan.
        top_n: Maximum number of results.
        min_bytes: Minimum file size to include.

    Returns:
        List of LargeFileResult sorted descending by size.
    """
    candidates = [f for f in files if f.size_bytes >= min_bytes]
    candidates.sort(key=lambda f: f.size_bytes, reverse=True)
    return [
        LargeFileResult(path=f.path, size_bytes=f.size_bytes)
        for f in candidates[:top_n]
    ]


# -- Directory sizes -------------------------------------------------------


def aggregate_directory_sizes(
    files: list[FileRecord],
    *,
    top_n: int = DEFAULT_DIR_SIZE_TOP_N,
) -> list[DirectorySizeResult]:
    """Aggregate file sizes by parent directory.

    Args:
        files: List of FileRecord from scan.
        top_n: Maximum number of results.

    Returns:
        List of DirectorySizeResult sorted descending by total size.
    """
    dir_sizes: dict[str, dict[str, int]] = defaultdict(
        lambda: {"size": 0, "count": 0}
    )
    for f in files:
        dir_sizes[f.parent_directory]["size"] += f.size_bytes
        dir_sizes[f.parent_directory]["count"] += 1

    results = [
        DirectorySizeResult(
            path=dir_path,
            total_size_bytes=info["size"],
            file_count=info["count"],
        )
        for dir_path, info in dir_sizes.items()
    ]
    results.sort(key=lambda r: r.total_size_bytes, reverse=True)
    return results[:top_n]


# -- File types ------------------------------------------------------------


def group_by_extension(files: list[FileRecord]) -> list[FileTypeGroup]:
    """Group files by extension and aggregate sizes.

    Files without an extension are grouped under '(no extension)'.

    Returns:
        List of FileTypeGroup sorted descending by total size.
    """
    groups: dict[str, dict[str, int]] = defaultdict(
        lambda: {"count": 0, "size": 0}
    )
    for f in files:
        ext = f.extension if f.extension else "(no extension)"
        groups[ext]["count"] += 1
        groups[ext]["size"] += f.size_bytes

    results = [
        FileTypeGroup(
            extension=ext,
            file_count=info["count"],
            total_size_bytes=info["size"],
        )
        for ext, info in groups.items()
    ]
    results.sort(key=lambda r: r.total_size_bytes, reverse=True)
    return results


# -- Recently modified files -----------------------------------------------


def find_recently_modified(
    files: list[FileRecord],
    *,
    days: int = DEFAULT_RECENT_DAYS,
    top_n: int = 50,
) -> list[FileRecord]:
    """Return files modified within the last N days.

    Args:
        files: List of FileRecord from scan.
        days: Number of days to look back.
        top_n: Maximum number of results.

    Returns:
        List of FileRecord sorted descending by modification time.
    """
    cutoff = time.time() - (days * 86400)
    recent = [f for f in files if f.modified_time >= cutoff]
    recent.sort(key=lambda f: f.modified_time, reverse=True)
    return recent[:top_n]


# -- Duplicate detection (staged) ------------------------------------------


def detect_duplicates(
    files: list[FileRecord],
    *,
    min_size: int = 1,
    max_groups: int = 100,
    hash_sample_size: int = 4096,
) -> list[DuplicateGroup]:
    """Detect probable duplicate files using a staged strategy.

    Stage 1: Group by file size.
    Stage 2: For groups with multiple files, compare first-chunk signature.
    Stage 3: For candidates that match, compute full hash.

    Args:
        files: List of FileRecord from scan.
        min_size: Minimum file size to consider (skip empty/tiny files).
        max_groups: Maximum duplicate groups to return.
        hash_sample_size: Bytes to read for initial signature comparison.

    Returns:
        List of DuplicateGroup with match information.
    """
    # Stage 1: Group by size
    size_groups: dict[int, list[FileRecord]] = defaultdict(list)
    for f in files:
        if f.size_bytes >= min_size:
            size_groups[f.size_bytes].append(f)

    # Filter to groups with 2+ files
    candidate_groups = {
        size: recs for size, recs in size_groups.items() if len(recs) >= 2
    }

    results: list[DuplicateGroup] = []
    group_id = 0

    for size, recs in candidate_groups.items():
        if len(results) >= max_groups:
            break

        # Stage 2: Compare first-chunk signatures for files > hash_sample_size
        if size > hash_sample_size:
            sig_groups: dict[str, list[FileRecord]] = defaultdict(list)
            for rec in recs:
                sig = _read_signature(rec.path, hash_sample_size)
                if sig is not None:
                    sig_groups[sig].append(rec)
                else:
                    # Cannot read -- put in its own group (won't match others)
                    sig_groups[f"unreadable_{rec.path}"].append(rec)

            # Stage 3: Full hash for signature-matching groups
            for sig, sig_recs in sig_groups.items():
                if len(sig_recs) < 2:
                    continue
                if len(results) >= max_groups:
                    break

                # Full hash comparison
                hash_groups: dict[str, list[str]] = defaultdict(list)
                for rec in sig_recs:
                    full_hash = _compute_full_hash(rec.path)
                    if full_hash is not None:
                        hash_groups[full_hash].append(rec.path)
                    else:
                        hash_groups[f"unreadable_{rec.path}"].append(rec.path)

                for hash_val, paths in hash_groups.items():
                    if len(paths) < 2:
                        continue
                    group_id += 1
                    results.append(
                        DuplicateGroup(
                            group_id=group_id,
                            size_bytes=size,
                            paths=sorted(paths),
                            match_type="hash",
                            hash_value=hash_val,
                        )
                    )
        else:
            # Small files: size match is sufficient
            if len(recs) >= 2:
                group_id += 1
                results.append(
                    DuplicateGroup(
                        group_id=group_id,
                        size_bytes=size,
                        paths=sorted(r.path for r in recs),
                        match_type="size",
                        hash_value=None,
                    )
                )

    return results


def _read_signature(path: str, size: int) -> str | None:
    """Read the first `size` bytes and return a hex digest, or None on error."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(size)
        return hashlib.sha256(chunk).hexdigest()
    except (OSError, PermissionError, ValueError):
        return None


def _compute_full_hash(path: str) -> str | None:
    """Compute SHA-256 hash of entire file, or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError, ValueError):
        return None
