"""Safe Temp Cleanup -- policy-driven remediation action.

disk.cleanup_temp is a policy-driven remediation action that identifies
eligible old temp files and sends them through the existing quarantine
mechanism.  It does NOT duplicate quarantine logic.

This action is NOT a generic filesystem cleanup tool.
It only operates on the current user's approved TEMP directory.
It NEVER permanently deletes files.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.remediation.quarantine import (
    EligibleFile,
    QuarantinePlan,
    QuarantineResult,
    check_file_eligibility,
    generate_quarantine_path,
    get_quarantine_dir,
    get_user_temp_dir,
    is_under_directory,
    scan_eligible_files,
    ensure_quarantine_dir,
)
import shutil


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGE_DAYS: int = 30
MIN_AGE_DAYS: int = 7
MAX_AGE_DAYS: int = 365
MAX_FILES_PER_EXECUTION: int = 500
PREVIEW_DISPLAY_LIMIT: int = 200


# ---------------------------------------------------------------------------
# Parameter validation
# ---------------------------------------------------------------------------


def validate_age_days(value: int | None) -> tuple[int, list[str]]:
    """Validate and return the age_days parameter.

    Returns (validated_value, errors).
    If errors is non-empty, the value is invalid.
    """
    errors: list[str] = []

    if value is None:
        return DEFAULT_AGE_DAYS, errors

    if not isinstance(value, int):
        errors.append(f"age_days must be an integer, got {type(value).__name__}")
        return DEFAULT_AGE_DAYS, errors

    if value < MIN_AGE_DAYS:
        errors.append(
            f"age_days must be at least {MIN_AGE_DAYS} days.  "
            f"A conservative minimum prevents accidental quarantine of "
            f"actively-in-use temporary files."
        )
        return DEFAULT_AGE_DAYS, errors

    if value > MAX_AGE_DAYS:
        errors.append(
            f"age_days must be at most {MAX_AGE_DAYS} days."
        )
        return DEFAULT_AGE_DAYS, errors

    return value, errors


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CleanupPreview:
    """Preview of what disk.cleanup_temp would do.

    This is read-only.  It does not modify the filesystem.
    """

    source_dir: str
    age_threshold_days: int
    files_examined: int
    candidates: int
    total_size_bytes: int
    candidate_files: list[EligibleFile]
    rollback_available: bool
    quarantine_dir: str
    warnings: list[str]
    skipped_files: list[tuple[str, str]]
    max_files_per_execution: int
    limit_exceeded: bool


@dataclass(frozen=True)
class MoveRecord:
    """Authoritative record of a single file move operation.

    Created immediately after a successful shutil.move.
    The successful move itself is the authoritative signal.
    """

    original_path: str
    quarantine_path: str
    original_size: int
    original_mtime: float
    original_mtime_iso: str
    quarantine_record_id: int | None = None
    record_persisted: bool = False
    persistence_error: str | None = None


@dataclass
class CleanupResult:
    """Result of executing disk.cleanup_temp.

    Uses existing quarantine infrastructure for moves.
    """

    files_examined: int = 0
    candidates: int = 0
    files_moved: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    bytes_moved: int = 0
    skip_reasons: dict[str, str] = field(default_factory=dict)
    failure_reasons: dict[str, str] = field(default_factory=dict)
    quarantine_record_ids: list[int] = field(default_factory=list)
    quarantine_dir: str = ""
    # Per-file move records — authoritative accounting of what actually moved
    move_records: list[MoveRecord] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Preview (read-only)
# ---------------------------------------------------------------------------


def preview_cleanup(
    temp_root: Path | None = None,
    age_days: int = DEFAULT_AGE_DAYS,
    quarantine_dir: Path | None = None,
) -> CleanupPreview:
    """Preview what disk.cleanup_temp would do without modifying anything.

    Uses existing scan_eligible_files from the quarantine module.
    Adds policy limits (MAX_FILES_PER_EXECUTION).

    Args:
        temp_root: The temp directory to scan.  If None, uses current
            user's TEMP.
        age_days: Minimum file age in days (7-365, default 30).
        quarantine_dir: Where files would be moved.  If None, uses
            default.

    Returns:
        CleanupPreview with eligibility information and limits.
    """
    validated_age, errors = validate_age_days(age_days)
    if errors:
        return CleanupPreview(
            source_dir="",
            age_threshold_days=age_days,
            files_examined=0,
            candidates=0,
            total_size_bytes=0,
            candidate_files=[],
            rollback_available=True,
            quarantine_dir="",
            warnings=errors,
            skipped_files=[],
            max_files_per_execution=MAX_FILES_PER_EXECUTION,
            limit_exceeded=False,
        )

    if temp_root is None:
        temp_root = get_user_temp_dir()
    if temp_root is None:
        return CleanupPreview(
            source_dir="unknown",
            age_threshold_days=validated_age,
            files_examined=0,
            candidates=0,
            total_size_bytes=0,
            candidate_files=[],
            rollback_available=True,
            quarantine_dir="",
            warnings=["Cannot determine user TEMP directory."],
            skipped_files=[],
            max_files_per_execution=MAX_FILES_PER_EXECUTION,
            limit_exceeded=False,
        )

    if quarantine_dir is None:
        quarantine_dir = get_quarantine_dir()

    eligible, examined, warnings = scan_eligible_files(
        temp_root, validated_age
    )

    # Sort deterministically by path
    eligible.sort(key=lambda f: str(f.path))

    # Check limit
    limit_exceeded = len(eligible) > MAX_FILES_PER_EXECUTION

    # Track skipped files
    skipped: list[tuple[str, str]] = []
    if limit_exceeded:
        skipped.append((
            f"{len(eligible) - MAX_FILES_PER_EXECUTION} files",
            f"exceeds MAX_FILES_PER_EXECUTION ({MAX_FILES_PER_EXECUTION})",
        ))

    total_size = sum(f.size for f in eligible)

    return CleanupPreview(
        source_dir=str(temp_root),
        age_threshold_days=validated_age,
        files_examined=examined,
        candidates=len(eligible),
        total_size_bytes=total_size,
        candidate_files=eligible[:PREVIEW_DISPLAY_LIMIT],
        rollback_available=True,
        quarantine_dir=str(quarantine_dir),
        warnings=warnings,
        skipped_files=skipped,
        max_files_per_execution=MAX_FILES_PER_EXECUTION,
        limit_exceeded=limit_exceeded,
    )


# ---------------------------------------------------------------------------
# Execute (uses existing quarantine infrastructure)
# ---------------------------------------------------------------------------


def execute_cleanup(
    temp_root: Path | None = None,
    age_days: int = DEFAULT_AGE_DAYS,
    quarantine_dir: Path | None = None,
) -> CleanupResult:
    """Execute disk.cleanup_temp by delegating to existing quarantine.

    This policy layer:
    1. Validates parameters
    2. Scans for eligible files
    3. Enforces MAX_FILES_PER_EXECUTION
    4. Delegates move to existing quarantine (shutil.move only)
    5. Returns structured result

    Args:
        temp_root: The temp directory to clean.  If None, uses current
            user's TEMP.
        age_days: Minimum file age in days (7-365, default 30).
        quarantine_dir: Where to move files.  If None, uses default.

    Returns:
        CleanupResult with execution details.
    """
    validated_age, errors = validate_age_days(age_days)
    if errors:
        return CleanupResult()

    if temp_root is None:
        temp_root = get_user_temp_dir()
    if temp_root is None:
        return CleanupResult()

    if quarantine_dir is None:
        quarantine_dir = get_quarantine_dir()

    eligible, examined, _warnings = scan_eligible_files(
        temp_root, validated_age
    )

    # Sort deterministically by path
    eligible.sort(key=lambda f: str(f.path))

    result = CleanupResult(
        files_examined=examined,
        candidates=len(eligible),
        quarantine_dir=str(quarantine_dir),
    )

    # Enforce limit
    if len(eligible) > MAX_FILES_PER_EXECUTION:
        result.files_skipped = len(eligible) - MAX_FILES_PER_EXECUTION
        result.skip_reasons["limit_exceeded"] = (
            f"{result.files_skipped} files skipped: "
            f"exceeds MAX_FILES_PER_EXECUTION ({MAX_FILES_PER_EXECUTION})"
        )
        eligible = eligible[:MAX_FILES_PER_EXECUTION]

    ensure_quarantine_dir(quarantine_dir)

    for ef in eligible:
        # TOCTOU revalidation immediately before move
        valid, reason = check_file_eligibility(
            ef.path, temp_root, validated_age
        )
        if not valid:
            result.files_skipped += 1
            result.skip_reasons[str(ef.path)] = reason
            continue

        # Verify size/mtime still consistent with preview
        try:
            current_stat = ef.path.stat()
            if current_stat.st_size != ef.size:
                result.files_skipped += 1
                result.skip_reasons[str(ef.path)] = (
                    f"size changed: {ef.size} -> {current_stat.st_size}"
                )
                continue
            if abs(current_stat.st_mtime - ef.mtime) > 1.0:
                result.files_skipped += 1
                result.skip_reasons[str(ef.path)] = (
                    f"mtime changed: {ef.mtime} -> {current_stat.st_mtime}"
                )
                continue
        except (OSError, PermissionError) as exc:
            result.files_skipped += 1
            result.skip_reasons[str(ef.path)] = f"cannot re-stat: {exc}"
            continue

        # Generate destination
        dest = generate_quarantine_path(
            quarantine_dir, ef.path, ef.mtime
        )

        # Check destination collision
        if dest is None:
            result.files_skipped += 1
            result.skip_reasons[str(ef.path)] = "destination collision"
            continue

        # Move using existing shutil.move (NEVER delete)
        try:
            from datetime import datetime, timezone
            original_mtime_iso = datetime.fromtimestamp(
                ef.mtime, tz=timezone.utc
            ).isoformat()
            shutil.move(str(ef.path), str(dest))
            # Move succeeded — create authoritative MoveRecord immediately
            move_record = MoveRecord(
                original_path=str(ef.path),
                quarantine_path=str(dest),
                original_size=ef.size,
                original_mtime=ef.mtime,
                original_mtime_iso=original_mtime_iso,
            )
            result.move_records.append(move_record)
            result.files_moved += 1
            result.bytes_moved += ef.size
        except (OSError, PermissionError) as exc:
            result.files_failed += 1
            result.failure_reasons[str(ef.path)] = str(exc)

    return result
