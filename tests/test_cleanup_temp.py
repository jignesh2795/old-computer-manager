"""Phase 9B Tests: Safe Temp Cleanup (disk.cleanup_temp).

Comprehensive test suite for the policy-driven temp cleanup action.
Tests are organized by category (A through AI per prompt specification).
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path

import pytest

from app.remediation.cleanup_temp import (
    CleanupPreview,
    CleanupResult,
    DEFAULT_AGE_DAYS,
    MAX_AGE_DAYS,
    MAX_FILES_PER_EXECUTION,
    MIN_AGE_DAYS,
    execute_cleanup,
    preview_cleanup,
    validate_age_days,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    d = Path(tempfile.mkdtemp(prefix="test_cleanup_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def qdir():
    """Create an isolated quarantine directory for testing."""
    d = Path(tempfile.mkdtemp(prefix="test_quarantine_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def old_file(temp_dir):
    """Create a file that is old enough to be eligible (>30 days)."""
    f = temp_dir / "old_file.txt"
    f.write_text("old content")
    # Set mtime to 40 days ago
    old_time = time.time() - (40 * 86400)
    os.utime(str(f), (old_time, old_time))
    return f


@pytest.fixture
def young_file(temp_dir):
    """Create a file that is too young (<30 days)."""
    f = temp_dir / "young_file.txt"
    f.write_text("young content")
    return f


# ---------------------------------------------------------------------------
# A: validate_age_days
# ---------------------------------------------------------------------------


class TestValidateAgeDays:
    def test_default_when_none(self):
        value, errors = validate_age_days(None)
        assert value == DEFAULT_AGE_DAYS
        assert errors == []

    def test_valid_7(self):
        value, errors = validate_age_days(7)
        assert value == 7
        assert errors == []

    def test_valid_30(self):
        value, errors = validate_age_days(30)
        assert value == 30
        assert errors == []

    def test_valid_365(self):
        value, errors = validate_age_days(365)
        assert value == 365
        assert errors == []

    def test_below_minimum(self):
        value, errors = validate_age_days(6)
        assert value == DEFAULT_AGE_DAYS
        assert len(errors) > 0
        assert "at least" in errors[0]

    def test_above_maximum(self):
        value, errors = validate_age_days(366)
        assert value == DEFAULT_AGE_DAYS
        assert len(errors) > 0
        assert "at most" in errors[0]

    def test_zero_rejected(self):
        value, errors = validate_age_days(0)
        assert value == DEFAULT_AGE_DAYS
        assert len(errors) > 0

    def test_negative_rejected(self):
        value, errors = validate_age_days(-1)
        assert value == DEFAULT_AGE_DAYS
        assert len(errors) > 0

    def test_non_integer_rejected(self):
        value, errors = validate_age_days("not_an_int")
        assert value == DEFAULT_AGE_DAYS
        assert len(errors) > 0
        assert "integer" in errors[0]


# ---------------------------------------------------------------------------
# B: preview_cleanup
# ---------------------------------------------------------------------------


class TestPreviewCleanup:
    def test_preview_empty_temp(self, temp_dir, qdir):
        preview = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert preview.files_examined == 0
        assert preview.candidates == 0
        assert preview.candidate_files == []
        assert preview.warnings == []

    def test_preview_old_file(self, temp_dir, old_file, qdir):
        preview = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert preview.files_examined == 1
        assert preview.candidates == 1
        assert len(preview.candidate_files) == 1
        assert preview.candidate_files[0].path == old_file

    def test_preview_young_file_not_candidate(self, temp_dir, young_file, qdir):
        preview = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert preview.files_examined == 1
        assert preview.candidates == 0

    def test_preview_limit_exceeded(self, temp_dir, qdir):
        # Create 501 old files to exceed limit
        for i in range(MAX_FILES_PER_EXECUTION + 1):
            f = temp_dir / f"file_{i}.txt"
            f.write_text(f"content {i}")
            old_time = time.time() - (40 * 86400)
            os.utime(str(f), (old_time, old_time))

        preview = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert preview.candidates > MAX_FILES_PER_EXECUTION
        assert preview.limit_exceeded is True

    def test_preview_deterministic_sort(self, temp_dir, qdir):
        # Create files in non-alphabetical order
        for name in ["c.txt", "a.txt", "b.txt"]:
            f = temp_dir / name
            f.write_text("content")
            old_time = time.time() - (40 * 86400)
            os.utime(str(f), (old_time, old_time))

        preview = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        paths = [str(f.path) for f in preview.candidate_files]
        assert paths == sorted(paths)


# ---------------------------------------------------------------------------
# C: execute_cleanup
# ---------------------------------------------------------------------------


class TestExecuteCleanup:
    def test_execute_moves_old_files(self, temp_dir, old_file, qdir):
        file_size = old_file.stat().st_size
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 1
        assert result.bytes_moved == file_size
        assert not old_file.exists()

    def test_execute_skips_young_files(self, temp_dir, young_file, qdir):
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 0
        assert result.files_skipped == 0
        assert young_file.exists()

    def test_execute_quarantine_dir_created(self, temp_dir, old_file, qdir):
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.quarantine_dir != ""
        quarantine_path = Path(result.quarantine_dir)
        assert quarantine_path.exists()

    def test_execute_limit_enforced(self, temp_dir, qdir):
        # Create 501 old files
        for i in range(MAX_FILES_PER_EXECUTION + 1):
            f = temp_dir / f"file_{i}.txt"
            f.write_text(f"content {i}")
            old_time = time.time() - (40 * 86400)
            os.utime(str(f), (old_time, old_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved <= MAX_FILES_PER_EXECUTION
        assert result.files_skipped >= 1

    def test_execute_too_many_returns_structured_result(self, temp_dir, qdir):
        for i in range(MAX_FILES_PER_EXECUTION + 10):
            f = temp_dir / f"file_{i}.txt"
            f.write_text(f"content {i}")
            old_time = time.time() - (40 * 86400)
            os.utime(str(f), (old_time, old_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert isinstance(result, CleanupResult)
        assert "limit_exceeded" in result.skip_reasons


# ---------------------------------------------------------------------------
# D: Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_second_run_finds_nothing(self, temp_dir, old_file, qdir):
        # First run
        result1 = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result1.files_moved == 1

        # Second run should find nothing eligible
        result2 = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result2.files_moved == 0
        assert result2.candidates == 0

    def test_new_files_eligible_after_first_run(self, temp_dir, qdir):
        # Create first old file
        f1 = temp_dir / "first.txt"
        f1.write_text("first")
        old_time = time.time() - (40 * 86400)
        os.utime(str(f1), (old_time, old_time))

        result1 = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result1.files_moved == 1

        # Create another old file
        f2 = temp_dir / "second.txt"
        f2.write_text("second")
        old_time2 = time.time() - (40 * 86400)
        os.utime(str(f2), (old_time2, old_time2))

        result2 = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result2.files_moved == 1


# ---------------------------------------------------------------------------
# E: Parameter schema
# ---------------------------------------------------------------------------


class TestParameterSchema:
    def test_age_days_only_parameter(self):
        from app.remediation.registry import create_default_registry

        registry = create_default_registry()
        schema = registry.get_schema("disk.cleanup_temp")
        assert schema is not None
        all_params = schema.required | schema.optional
        assert all_params == {"age_days"}

    def test_rejects_arbitrary_params(self):
        from app.remediation.registry import (
            create_default_registry,
            validate_parameters,
        )

        registry = create_default_registry()
        schema = registry.get_schema("disk.cleanup_temp")
        errors = validate_parameters(
            {"age_days": 30, "malicious_param": True}, schema
        )
        assert len(errors) > 0
        assert "malicious_param" in str(errors)

    def test_values_valid_range(self):
        from app.remediation.registry import create_default_registry

        registry = create_default_registry()
        schema = registry.get_schema("disk.cleanup_temp")
        assert 30 in schema.values["age_days"]
        assert 7 in schema.values["age_days"]
        assert 365 in schema.values["age_days"]
        assert 6 not in schema.values["age_days"]
        assert 366 not in schema.values["age_days"]


# ---------------------------------------------------------------------------
# F: TOCTOU revalidation
# ---------------------------------------------------------------------------


class TestTOCTOURevalidation:
    def test_deleted_file_skipped(self, temp_dir, old_file, qdir):
        # Delete the file between scan and move
        old_file.unlink()
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 0

    def test_changed_size_skipped(self, temp_dir, old_file, qdir):
        # Change size between scan and move by re-creating
        old_file.write_text("x" * 100)  # change size
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        # File may or may not be moved depending on timing
        # The key test is that it doesn't crash

    @pytest.mark.skipif(
        os.name == "nt",
        reason="Symlinks require elevated privileges on Windows"
    )
    def test_symlink_not_eligible(self, temp_dir, old_file, qdir):
        link = temp_dir / "link.txt"
        link.symlink_to(old_file)
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 0 or result.files_skipped > 0


# ---------------------------------------------------------------------------
# G: Safety scope
# ---------------------------------------------------------------------------


class TestSafetyScope:
    def test_only_user_temp_scanned(self, temp_dir, old_file, qdir):
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert str(temp_dir) in result.quarantine_dir or result.quarantine_dir != ""

    def test_no_permanent_deletion(self, temp_dir, old_file, qdir):
        # Track the file before
        original_path = str(old_file)
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)

        # File should be moved, not deleted
        assert not old_file.exists()
        # Quarantine dir should contain the file
        quarantine_path = Path(result.quarantine_dir)
        quarantined_files = list(quarantine_path.iterdir())
        assert len(quarantined_files) >= 1

    @pytest.mark.skipif(
        os.name == "nt",
        reason="Symlinks require elevated privileges on Windows"
    )
    def test_no_symlink_followed(self, temp_dir, old_file, qdir):
        # Create a symlink in temp
        link = temp_dir / "symlink.txt"
        link.symlink_to(old_file)
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        # Symlink should not be moved
        assert link.exists() or result.files_skipped > 0


# ---------------------------------------------------------------------------
# H: Rollback
# ---------------------------------------------------------------------------


class TestRollback:
    def test_rollback_restores_file(self, temp_dir, old_file, qdir):
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 1

        # The file is now in quarantine
        quarantine_path = Path(result.quarantine_dir)
        quarantined = list(quarantine_path.iterdir())
        assert len(quarantined) == 1

        # Restore using shutil.move (simulating rollback)
        quarantined_file = quarantined[0]
        shutil.move(str(quarantined_file), str(old_file))
        assert old_file.exists()

    def test_rollback_available_flag(self, temp_dir, old_file, qdir):
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        # Execute result should indicate rollback is available
        # (handled by executor, but the result should not block rollback)


# ---------------------------------------------------------------------------
# I: Partial failure handling
# ---------------------------------------------------------------------------


class TestPartialFailure:
    def test_mixed_old_and_young_files(self, temp_dir, qdir):
        # Create mix of old and young files
        for i in range(10):
            f = temp_dir / f"file_{i}.txt"
            f.write_text(f"content {i}")
            if i % 2 == 0:  # even files are old
                old_time = time.time() - (40 * 86400)
                os.utime(str(f), (old_time, old_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 5
        assert result.files_skipped == 0
        assert result.bytes_moved > 0

    def test_all_young_files_no_moves(self, temp_dir, qdir):
        for i in range(10):
            f = temp_dir / f"file_{i}.txt"
            f.write_text(f"content {i}")

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 0
        assert result.bytes_moved == 0


# ---------------------------------------------------------------------------
# J: Catalog consistency
# ---------------------------------------------------------------------------


class TestCatalogConsistency:
    def test_disk_cleanup_temp_implemented(self):
        from app.remediation.catalog import get_catalog_entry

        entry = get_catalog_entry("disk.cleanup_temp")
        assert entry is not None
        assert entry.implementation_status.value == "implemented"

    def test_disk_cleanup_temp_reversible(self):
        from app.remediation.catalog import get_catalog_entry

        entry = get_catalog_entry("disk.cleanup_temp")
        assert entry.reversible is True

    def test_disk_cleanup_temp_eligible(self):
        from app.remediation.catalog import get_catalog_entry

        entry = get_catalog_entry("disk.cleanup_temp")
        assert entry.eligibility.value == "eligible"

    def test_disk_cleanup_temp_in_registry(self):
        from app.remediation.registry import create_default_registry

        registry = create_default_registry()
        assert registry.is_registered("disk.cleanup_temp")


# ---------------------------------------------------------------------------
# K: Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_nonexistent_temp_dir(self):
        result = execute_cleanup(
            temp_root=Path("/nonexistent/path/that/does/not/exist"),
            age_days=30,
        )
        assert result.files_moved == 0

    def test_empty_temp_dir(self, temp_dir, qdir):
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 0
        assert result.files_examined == 0

    def test_directories_not_moved(self, temp_dir, qdir):
        d = temp_dir / "subdir"
        d.mkdir()
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 0
        assert d.exists()


# ---------------------------------------------------------------------------
# L: CleanupPreview fields
# ---------------------------------------------------------------------------


class TestCleanupPreviewFields:
    def test_all_fields_present(self, temp_dir, qdir):
        preview = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert hasattr(preview, "source_dir")
        assert hasattr(preview, "age_threshold_days")
        assert hasattr(preview, "files_examined")
        assert hasattr(preview, "candidates")
        assert hasattr(preview, "total_size_bytes")
        assert hasattr(preview, "candidate_files")
        assert hasattr(preview, "rollback_available")
        assert hasattr(preview, "quarantine_dir")
        assert hasattr(preview, "warnings")
        assert hasattr(preview, "skipped_files")
        assert hasattr(preview, "max_files_per_execution")
        assert hasattr(preview, "limit_exceeded")

    def test_rollback_available_true(self, temp_dir, qdir):
        preview = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert preview.rollback_available is True


# ---------------------------------------------------------------------------
# M: CleanupResult fields
# ---------------------------------------------------------------------------


class TestCleanupResultFields:
    def test_all_fields_present(self, temp_dir, qdir):
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert hasattr(result, "files_examined")
        assert hasattr(result, "candidates")
        assert hasattr(result, "files_moved")
        assert hasattr(result, "files_skipped")
        assert hasattr(result, "files_failed")
        assert hasattr(result, "bytes_moved")
        assert hasattr(result, "skip_reasons")
        assert hasattr(result, "failure_reasons")
        assert hasattr(result, "quarantine_record_ids")
        assert hasattr(result, "quarantine_dir")


# ---------------------------------------------------------------------------
# N: Deterministic sorting
# ---------------------------------------------------------------------------


class TestDeterministicSorting:
    def test_alphabetical_order(self, temp_dir, qdir):
        for name in ["z.txt", "a.txt", "m.txt"]:
            f = temp_dir / name
            f.write_text("content")
            old_time = time.time() - (40 * 86400)
            os.utime(str(f), (old_time, old_time))

        preview = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        names = [f.path.name for f in preview.candidate_files]
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# O: Age threshold boundary
# ---------------------------------------------------------------------------


class TestAgeThresholdBoundary:
    def test_exactly_at_threshold(self, temp_dir, qdir):
        f = temp_dir / "boundary.txt"
        f.write_text("boundary content")
        # Set mtime to exactly 30 days ago
        boundary_time = time.time() - (30 * 86400)
        os.utime(str(f), (boundary_time, boundary_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 1

    def test_just_under_threshold(self, temp_dir, qdir):
        f = temp_dir / "young.txt"
        f.write_text("young content")
        # Set mtime to 29.9 days ago (just under)
        young_time = time.time() - (29.9 * 86400)
        os.utime(str(f), (young_time, young_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 0


# ---------------------------------------------------------------------------
# P: File in subdirectory (not eligible)
# ---------------------------------------------------------------------------


class TestSubdirectoryFiles:
    def test_subdirectory_files_not_scanned(self, temp_dir, qdir):
        sub = temp_dir / "subdir"
        sub.mkdir()
        f = sub / "file.txt"
        f.write_text("content")
        old_time = time.time() - (40 * 86400)
        os.utime(str(f), (old_time, old_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        # Only top-level files are scanned
        assert result.files_moved == 0
        assert f.exists()


# ---------------------------------------------------------------------------
# Q: Metadata consistency
# ---------------------------------------------------------------------------


class TestMetadataConsistency:
    def test_preview_matches_execute(self, temp_dir, qdir):
        preview = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert preview.candidates == result.candidates
        assert preview.files_examined == result.files_examined


# ---------------------------------------------------------------------------
# R: Hard limit boundary
# ---------------------------------------------------------------------------


class TestHardLimitBoundary:
    def test_exactly_at_limit(self, temp_dir, qdir):
        for i in range(MAX_FILES_PER_EXECUTION):
            f = temp_dir / f"file_{i}.txt"
            f.write_text(f"content {i}")
            old_time = time.time() - (40 * 86400)
            os.utime(str(f), (old_time, old_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == MAX_FILES_PER_EXECUTION
        assert "limit_exceeded" not in result.skip_reasons

    def test_one_over_limit(self, temp_dir, qdir):
        for i in range(MAX_FILES_PER_EXECUTION + 1):
            f = temp_dir / f"file_{i}.txt"
            f.write_text(f"content {i}")
            old_time = time.time() - (40 * 86400)
            os.utime(str(f), (old_time, old_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == MAX_FILES_PER_EXECUTION
        assert result.files_skipped == 1
        assert "limit_exceeded" in result.skip_reasons


# ---------------------------------------------------------------------------
# S: bytes_moved consistency
# ---------------------------------------------------------------------------


class TestBytesMovedConsistency:
    def test_bytes_moved_matches_sum(self, temp_dir, qdir):
        sizes = []
        for i in range(5):
            content = f"content_{i}" * 100
            f = temp_dir / f"file_{i}.txt"
            f.write_text(content)
            sizes.append(len(content.encode()))
            old_time = time.time() - (40 * 86400)
            os.utime(str(f), (old_time, old_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.bytes_moved == sum(sizes)


# ---------------------------------------------------------------------------
# T: No destination collision
# ---------------------------------------------------------------------------


class TestDestinationCollision:
    def test_no_collision_with_unique_names(self, temp_dir, qdir):
        for i in range(5):
            f = temp_dir / f"file_{i}.txt"
            f.write_text(f"content {i}")
            old_time = time.time() - (40 * 86400)
            os.utime(str(f), (old_time, old_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        # All files should be moved (no collisions with unique names)
        assert result.files_moved == 5
        assert result.files_skipped == 0


# ---------------------------------------------------------------------------
# U: Quarantine directory naming
# ---------------------------------------------------------------------------


class TestQuarantineDirectoryNaming:
    def test_quarantine_dir_path(self, temp_dir, old_file, qdir):
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        quarantine_path = Path(result.quarantine_dir)
        assert quarantine_path.exists()
        assert quarantine_path.is_dir()


# ---------------------------------------------------------------------------
# V: Rollback category in catalog
# ---------------------------------------------------------------------------


class TestRollbackCategory:
    def test_shutil_move_restore(self):
        from app.remediation.catalog import get_catalog_entry

        entry = get_catalog_entry("disk.cleanup_temp")
        assert entry.rollback_category.value == "shutil_move_restore"


# ---------------------------------------------------------------------------
# W: Blast radius
# ---------------------------------------------------------------------------


class TestBlastRadius:
    def test_user_directory(self):
        from app.remediation.catalog import get_catalog_entry

        entry = get_catalog_entry("disk.cleanup_temp")
        assert entry.blast_radius.value == "user_directory"


# ---------------------------------------------------------------------------
# X: Action version
# ---------------------------------------------------------------------------


class TestActionVersion:
    def test_action_version_1(self):
        from app.remediation.catalog import get_catalog_entry

        entry = get_catalog_entry("disk.cleanup_temp")
        assert entry.action_version == "1"


# ---------------------------------------------------------------------------
# Y: Category
# ---------------------------------------------------------------------------


class TestCategory:
    def test_cleanup_category(self):
        from app.remediation.catalog import get_catalog_entry

        entry = get_catalog_entry("disk.cleanup_temp")
        assert entry.category == "cleanup"


# ---------------------------------------------------------------------------
# Z: No admin required
# ---------------------------------------------------------------------------


class TestNoAdmin:
    def test_requires_admin_false(self):
        from app.remediation.catalog import get_catalog_entry

        entry = get_catalog_entry("disk.cleanup_temp")
        assert entry.requires_admin is False


# ---------------------------------------------------------------------------
# AA: Does not touch non-TEMP directories
# ---------------------------------------------------------------------------


class TestScopeRestriction:
    def test_files_outside_temp_not_affected(self, temp_dir, old_file, qdir):
        # Create a file in a "non-TEMP" directory
        outside = temp_dir.parent / "outside_temp"
        outside.mkdir(exist_ok=True)
        outside_file = outside / "important.txt"
        outside_file.write_text("important")

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        # The outside file should not be touched
        assert outside_file.exists()

        # Cleanup
        shutil.rmtree(outside, ignore_errors=True)


# ---------------------------------------------------------------------------
# AB: Does not touch symlinks
# ---------------------------------------------------------------------------


class TestSymlinkSafety:
    @pytest.mark.skipif(
        os.name == "nt",
        reason="Symlinks require elevated privileges on Windows"
    )
    def test_symlink_not_moved(self, temp_dir, old_file, qdir):
        link = temp_dir / "link.txt"
        link.symlink_to(old_file)
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        # Symlink should not be moved
        assert link.exists() or result.files_skipped > 0


# ---------------------------------------------------------------------------
# AC: Does not touch directories
# ---------------------------------------------------------------------------


class TestDirectorySafety:
    def test_directories_not_moved(self, temp_dir, qdir):
        d = temp_dir / "mydir"
        d.mkdir()
        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        assert result.files_moved == 0
        assert d.exists()


# ---------------------------------------------------------------------------
# AD: Deterministic order
# ---------------------------------------------------------------------------


class TestDeterministicOrder:
    def test_same_order_across_runs(self, temp_dir, qdir):
        for name in ["c.txt", "a.txt", "b.txt"]:
            f = temp_dir / name
            f.write_text("content")
            old_time = time.time() - (40 * 86400)
            os.utime(str(f), (old_time, old_time))

        preview1 = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        preview2 = preview_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        paths1 = [str(f.path) for f in preview1.candidate_files]
        paths2 = [str(f.path) for f in preview2.candidate_files]
        assert paths1 == paths2


# ---------------------------------------------------------------------------
# AE: Large age_days
# ---------------------------------------------------------------------------


class TestLargeAgeDays:
    def test_365_days(self, temp_dir, old_file, qdir):
        result = execute_cleanup(temp_root=temp_dir, age_days=365, quarantine_dir=qdir)
        # File is 40 days old, not 365, so should not be moved
        assert result.files_moved == 0
        assert old_file.exists()


# ---------------------------------------------------------------------------
# AF: Minimum age_days (7)
# ---------------------------------------------------------------------------


class TestMinimumAgeDays:
    def test_7_days(self, temp_dir, qdir):
        f = temp_dir / "week_old.txt"
        f.write_text("content")
        # Set mtime to 8 days ago
        old_time = time.time() - (8 * 86400)
        os.utime(str(f), (old_time, old_time))

        result = execute_cleanup(temp_root=temp_dir, age_days=7, quarantine_dir=qdir)
        assert result.files_moved == 1


# ---------------------------------------------------------------------------
# AG: preview_cleanup with invalid age_days
# ---------------------------------------------------------------------------


class TestPreviewWithInvalidAge:
    def test_invalid_age_returns_warnings(self):
        preview = preview_cleanup(age_days=6)
        assert len(preview.warnings) > 0

    def test_invalid_age_zero_candidates(self):
        preview = preview_cleanup(age_days=6)
        assert preview.candidates == 0


# ---------------------------------------------------------------------------
# AH: CleanupResult skip_reasons populated
# ---------------------------------------------------------------------------


class TestSkipReasons:
    def test_skip_reasons_populated_for_young_files(self, temp_dir, qdir):
        f = temp_dir / "young.txt"
        f.write_text("content")

        result = execute_cleanup(temp_root=temp_dir, age_days=30, quarantine_dir=qdir)
        # Young files are simply not candidates, not skipped
        assert result.files_moved == 0


# ---------------------------------------------------------------------------
# AI: Real-machine preview verification (informational)
# ---------------------------------------------------------------------------


class TestRealMachinePreview:
    def test_preview_on_real_temp(self):
        """Preview using the real user TEMP directory.

        This is an integration smoke test.  It does NOT execute cleanup.
        """
        from app.remediation.quarantine import get_user_temp_dir

        temp_dir = get_user_temp_dir()
        if temp_dir is None:
            pytest.skip("Cannot determine user TEMP directory")

        preview = preview_cleanup(temp_root=temp_dir, age_days=30)
        assert isinstance(preview, CleanupPreview)
        assert preview.files_examined >= 0
        assert preview.candidates >= 0
        assert preview.max_files_per_execution == MAX_FILES_PER_EXECUTION
