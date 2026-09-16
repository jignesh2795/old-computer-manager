"""Quarantine logic -- scan, move, rollback for temporary files.

This is the first real remediation action.  It quarantines eligible
temporary files by MOVING them into an application-managed quarantine
directory.  It NEVER permanently deletes files.
"""

from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePath
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum number of files to display in preview results.
_PREVIEW_DISPLAY_LIMIT = 200

# The only approved temp root for this action (per-user TEMP).
_APPROVED_TEMP_ENV_VARS = ("TEMP", "TMP")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EligibleFile:
    """A file that passed all eligibility checks."""

    path: Path
    size: int
    mtime: float
    mtime_iso: str


@dataclass(frozen=True)
class QuarantinePlan:
    """Preview of what quarantine would do.

    Attributes:
        source_dir: The temp directory being quarantined.
        age_threshold_days: How old files must be.
        files_examined: Total files checked.
        files_eligible: Files that passed eligibility.
        total_size_bytes: Sum of eligible file sizes.
        eligible_files: List of eligible files (up to display limit).
        rollback_available: Whether rollback is supported.
        quarantine_dir: Where files would be moved.
        warnings: Any warnings encountered during scan.
    """

    source_dir: str
    age_threshold_days: int
    files_examined: int
    files_eligible: int
    total_size_bytes: int
    eligible_files: list[EligibleFile]
    rollback_available: bool = True
    quarantine_dir: str = ""
    warnings: list[str] = field(default_factory=list)


@dataclass
class QuarantineResult:
    """Result of executing quarantine.

    Attributes:
        files_examined: Total files checked.
        files_eligible: Files that passed eligibility.
        files_moved: Files successfully moved.
        files_skipped: Files skipped (changed, access denied, etc.).
        files_failed: Files that failed to move.
        total_bytes_moved: Sum of moved file sizes.
        failure_reasons: Per-file failure reasons.
        quarantine_record_ids: IDs of created quarantine records.
        quarantine_dir: Where files were moved.
    """

    files_examined: int = 0
    files_eligible: int = 0
    files_moved: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    total_bytes_moved: int = 0
    failure_reasons: dict[str, str] = field(default_factory=dict)
    quarantine_record_ids: list[int] = field(default_factory=list)
    quarantine_dir: str = ""


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------


def get_user_temp_dir() -> Path | None:
    """Return the current user's TEMP directory, or None if unknown.

    Only resolves from known environment variables.  Does NOT trust
    arbitrary input.
    """
    for env_var in _APPROVED_TEMP_ENV_VARS:
        raw = os.environ.get(env_var)
        if raw:
            resolved = Path(raw).resolve()
            # Verify it looks like a per-user temp dir (not system root)
            if resolved.is_dir():
                return resolved
    return None


def is_under_directory(path: Path, parent: Path) -> bool:
    """Check whether *path* is contained under *parent*.

    Uses resolve() to canonicalize both paths.  Returns False if
    resolution fails (e.g. broken symlink).
    """
    try:
        resolved_path = path.resolve()
        resolved_parent = parent.resolve()
        # Check by prefix on resolved absolute paths
        return str(resolved_path).startswith(str(resolved_parent) + os.sep) or resolved_path == resolved_parent
    except (OSError, ValueError):
        return False


def safe_resolve(path: Path) -> Path | None:
    """Resolve a path safely, returning None on failure.

    Does NOT follow symlinks for the final component -- uses
    os.path.realpath which does follow symlinks.  For symlink checks,
    the caller must use lstat or is_symlink separately.
    """
    try:
        return path.resolve()
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Eligibility checks
# ---------------------------------------------------------------------------


def check_file_eligibility(
    path: Path,
    temp_root: Path,
    age_threshold_days: int,
) -> tuple[bool, str]:
    """Check whether a single file is eligible for quarantine.

    Returns (eligible, reason).
    """
    try:
        # Must not be a symlink
        if path.is_symlink():
            return False, "symlink"

        # Must be a regular file
        if not path.is_file():
            return False, "not a regular file"

        # Must be under approved temp root
        if not is_under_directory(path, temp_root):
            return False, "outside approved temp root"

        # Check age
        try:
            stat = path.stat()
        except (OSError, PermissionError) as exc:
            return False, f"cannot stat: {exc}"

        age_seconds = time.time() - stat.st_mtime
        age_days = age_seconds / 86400
        if age_days < age_threshold_days:
            return False, f"too young ({age_days:.1f} days < {age_threshold_days} days)"

        return True, "eligible"

    except (OSError, PermissionError) as exc:
        return False, f"error: {exc}"


def scan_eligible_files(
    temp_root: Path,
    age_threshold_days: int,
) -> tuple[list[EligibleFile], int, list[str]]:
    """Scan the temp directory for eligible files.

    Returns (eligible_files, files_examined, warnings).
    """
    eligible: list[EligibleFile] = []
    examined = 0
    warnings: list[str] = []

    if not temp_root.is_dir():
        warnings.append(f"Temp directory does not exist: {temp_root}")
        return eligible, examined, warnings

    try:
        entries = list(temp_root.iterdir())
    except PermissionError as exc:
        warnings.append(f"Cannot read temp directory: {exc}")
        return eligible, examined, warnings

    for entry in entries:
        # Skip directories entirely
        if entry.is_dir():
            continue

        examined += 1

        eligible_flag, reason = check_file_eligibility(
            entry, temp_root, age_threshold_days
        )

        if eligible_flag:
            try:
                stat = entry.stat()
                mtime_iso = datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).isoformat()
                eligible.append(EligibleFile(
                    path=entry,
                    size=stat.st_size,
                    mtime=stat.st_mtime,
                    mtime_iso=mtime_iso,
                ))
            except (OSError, PermissionError) as exc:
                warnings.append(f"Cannot stat eligible file {entry}: {exc}")

    return eligible, examined, warnings


# ---------------------------------------------------------------------------
# Quarantine directory
# ---------------------------------------------------------------------------


def get_quarantine_dir(app_data_dir: Path | None = None) -> Path:
    """Return the quarantine directory path.

    Uses the application's own data directory if provided, otherwise
    falls back to ~/.old-computer-manager/quarantine.
    """
    if app_data_dir is not None:
        return app_data_dir / "quarantine"
    return Path.home() / ".old-computer-manager" / "quarantine"


def ensure_quarantine_dir(quarantine_dir: Path) -> None:
    """Create the quarantine directory if it does not exist."""
    quarantine_dir.mkdir(parents=True, exist_ok=True)


def generate_quarantine_path(
    quarantine_dir: Path,
    original_path: Path,
    original_mtime: float,
) -> Path | None:
    """Generate a unique quarantine path for a file.

    Uses a timestamp prefix and the original filename.  Returns None
    if the path already exists (collision), to prevent overwriting.
    """
    ts = int(original_mtime)
    basename = original_path.name
    # Use first 64 chars of basename to keep paths manageable
    short_name = basename[:64] if len(basename) > 64 else basename
    candidate = quarantine_dir / f"{ts}_{short_name}"

    if candidate.exists():
        return None
    return candidate


# ---------------------------------------------------------------------------
# Preview (read-only)
# ---------------------------------------------------------------------------


def preview_quarantine(
    temp_root: Path | None = None,
    age_threshold_days: int = 7,
    quarantine_dir: Path | None = None,
) -> QuarantinePlan:
    """Preview what quarantine would do without modifying anything.

    Args:
        temp_root: The temp directory to scan.  If None, uses current
            user's TEMP.
        age_threshold_days: Minimum file age in days.
        quarantine_dir: Where files would be moved.  If None, uses
            default.

    Returns:
        QuarantinePlan with all eligibility information.
    """
    if temp_root is None:
        temp_root = get_user_temp_dir()
    if temp_root is None:
        return QuarantinePlan(
            source_dir="unknown",
            age_threshold_days=age_threshold_days,
            files_examined=0,
            files_eligible=0,
            total_size_bytes=0,
            eligible_files=[],
            rollback_available=True,
            warnings=["Cannot determine user TEMP directory."],
        )

    if quarantine_dir is None:
        quarantine_dir = get_quarantine_dir()

    eligible, examined, warnings = scan_eligible_files(
        temp_root, age_threshold_days
    )

    total_size = sum(f.size for f in eligible)

    return QuarantinePlan(
        source_dir=str(temp_root),
        age_threshold_days=age_threshold_days,
        files_examined=examined,
        files_eligible=len(eligible),
        total_size_bytes=total_size,
        eligible_files=eligible[:_PREVIEW_DISPLAY_LIMIT],
        rollback_available=True,
        quarantine_dir=str(quarantine_dir),
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Execute quarantine
# ---------------------------------------------------------------------------


def execute_quarantine(
    temp_root: Path | None = None,
    age_threshold_days: int = 7,
    quarantine_dir: Path | None = None,
    *,
    dry_run: bool = False,
) -> QuarantineResult:
    """Execute the quarantine operation.

    Args:
        temp_root: The temp directory to quarantine.  If None, uses
            current user's TEMP.
        age_threshold_days: Minimum file age in days.
        quarantine_dir: Where to move files.  If None, uses default.
        dry_run: If True, only scan without moving files.

    Returns:
        QuarantineResult with execution details.
    """
    if temp_root is None:
        temp_root = get_user_temp_dir()
    if temp_root is None:
        return QuarantineResult()

    if quarantine_dir is None:
        quarantine_dir = get_quarantine_dir()

    eligible, examined, _warnings = scan_eligible_files(
        temp_root, age_threshold_days
    )

    result = QuarantineResult(
        files_examined=examined,
        files_eligible=len(eligible),
        quarantine_dir=str(quarantine_dir),
    )

    if dry_run:
        return result

    ensure_quarantine_dir(quarantine_dir)

    for ef in eligible:
        # Revalidate immediately before move (TOCTOU protection)
        valid, reason = check_file_eligibility(
            ef.path, temp_root, age_threshold_days
        )
        if not valid:
            result.files_skipped += 1
            result.failure_reasons[str(ef.path)] = reason
            continue

        # Generate destination
        dest = generate_quarantine_path(
            quarantine_dir, ef.path, ef.mtime
        )

        # Check destination collision
        if dest is None:
            result.files_skipped += 1
            result.failure_reasons[str(ef.path)] = "destination collision"
            continue

        try:
            shutil.move(str(ef.path), str(dest))
            result.files_moved += 1
            result.total_bytes_moved += ef.size
        except (OSError, PermissionError) as exc:
            result.files_failed += 1
            result.failure_reasons[str(ef.path)] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


def rollback_quarantine(
    quarantine_record_id: int,
    quarantine_store: Any,
    *,
    overwrite: bool = False,
) -> tuple[bool, str]:
    """Restore a quarantined file to its original location.

    Args:
        quarantine_record_id: ID of the quarantine record to restore.
        quarantine_store: QuarantineStore instance for database access.
        overwrite: If True, overwrite an existing file at the original
            path.  Default is False (refuse to overwrite).

    Returns:
        (success, message)
    """
    record = quarantine_store.get_record(quarantine_record_id)
    if record is None:
        return False, f"Quarantine record {quarantine_record_id} not found."

    if record.restored:
        return False, f"Record {quarantine_record_id} was already restored."

    quarantine_path = Path(record.quarantine_path)
    original_path = Path(record.original_path)

    # Verify quarantine file still exists
    if not quarantine_path.exists():
        return False, (
            f"Quarantine file no longer exists: {quarantine_path}"
        )

    # Verify original destination is safe
    if original_path.exists() and not overwrite:
        return False, (
            f"Original path already exists and overwrite=False: {original_path}"
        )

    # Verify original parent directory exists
    parent = original_path.parent
    if not parent.exists():
        return False, (
            f"Original parent directory does not exist: {parent}"
        )

    # Perform the restore
    try:
        shutil.move(str(quarantine_path), str(original_path))
        quarantine_store.mark_restored(quarantine_record_id)
        return True, f"Restored to {original_path}"
    except (OSError, PermissionError) as exc:
        return False, f"Restore failed: {exc}"
