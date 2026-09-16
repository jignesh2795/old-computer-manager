"""Data models for file analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FileRecord:
    """A single file observed during a scan.

    Attributes:
        path: Absolute resolved path.
        size_bytes: File size in bytes.
        modified_time: Last modification time (epoch seconds).
        created_time: Creation time if available (epoch seconds), else None.
        extension: Lowercase extension including dot (e.g. '.txt'), or ''.
        filename: Base filename.
        parent_directory: Absolute path of parent directory.
        scan_root: The root directory this file was scanned under.
    """

    path: str
    size_bytes: int
    modified_time: float
    created_time: float | None
    extension: str
    filename: str
    parent_directory: str
    scan_root: str


@dataclass
class ScanStats:
    """Aggregate statistics from a scan run.

    Mutable -- the scanner updates fields incrementally during traversal.
    """

    roots_scanned: int = 0
    files_examined: int = 0
    directories_examined: int = 0
    bytes_examined: int = 0
    files_skipped: int = 0
    inaccessible_items: int = 0
    symlinks_skipped: int = 0
    excluded_items: int = 0
    elapsed_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LargeFileResult:
    """A single entry in the large-file report."""

    path: str
    size_bytes: int


@dataclass(frozen=True)
class DirectorySizeResult:
    """Aggregated directory size entry."""

    path: str
    total_size_bytes: int
    file_count: int


@dataclass(frozen=True)
class FileTypeGroup:
    """File-type aggregation entry."""

    extension: str
    file_count: int
    total_size_bytes: int


@dataclass(frozen=True)
class DuplicateGroup:
    """A group of probable duplicate files (same size)."""

    group_id: int
    size_bytes: int
    paths: list[str] = field(default_factory=list)
    match_type: str = "size"  # "size" or "hash"
    hash_value: str | None = None


@dataclass(frozen=True)
class ScanResult:
    """Complete result of a file scan with analysis."""

    scan_root: str
    stats: ScanStats
    large_files: list[LargeFileResult] = field(default_factory=list)
    directory_sizes: list[DirectorySizeResult] = field(default_factory=list)
    file_type_groups: list[FileTypeGroup] = field(default_factory=list)
    recently_modified: list[FileRecord] = field(default_factory=list)
    duplicate_groups: list[DuplicateGroup] = field(default_factory=list)
