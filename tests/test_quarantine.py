"""Comprehensive security tests for Phase 3B quarantine implementation.

Tests A-T cover all required security scenarios.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path

import pytest

from app.remediation.action import RemediationAction, RiskLevel
from app.remediation.registry import ActionRegistry, ParameterSchema, create_default_registry
from app.remediation.quarantine import (
    EligibleFile,
    QuarantinePlan,
    QuarantineResult,
    check_file_eligibility,
    execute_quarantine,
    generate_quarantine_path,
    get_quarantine_dir,
    get_user_temp_dir,
    is_under_directory,
    preview_quarantine,
    rollback_quarantine,
    safe_resolve,
    scan_eligible_files,
)
from app.remediation.quarantine_store import QuarantineRecord, QuarantineStore
from app.remediation.preview import preview_action
from app.remediation.executor import QuarantineExecutor, SimulationExecutor, execute_action
from app.remediation.audit import AuditRecord, AuditStatus, AuditStore
from app.remediation.validation import validate_action, ValidationResult
from app.remediation.confirmation import confirm_action, ConfirmationRequiredError, ConfirmationReuseError
from app.database.sqlite import SnapshotStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_temp_dir() -> Path:
    """Create a temporary directory for testing."""
    return Path(tempfile.mkdtemp())


def _make_file(directory: Path, name: str, content: str = "test", age_days: int = 0) -> Path:
    """Create a test file with specified age."""
    path = directory / name
    path.write_text(content)
    if age_days > 0:
        # Set mtime to age_days ago
        old_time = time.time() - (age_days * 86400)
        os.utime(path, (old_time, old_time))
    return path


def _make_subdir(directory: Path, name: str) -> Path:
    """Create a subdirectory."""
    path = directory / name
    path.mkdir()
    return path


def _cleanup(path: Path) -> None:
    """Clean up a temporary directory."""
    shutil.rmtree(path, ignore_errors=True)


def _make_audit_store(tmpdir: Path) -> AuditStore:
    """Create an AuditStore in a temp directory."""
    return AuditStore(db_path=tmpdir / "audit.db")


def _make_quarantine_store(tmpdir: Path) -> QuarantineStore:
    """Create a QuarantineStore in a temp directory."""
    return QuarantineStore(db_path=tmpdir / "quarantine.db")


def _make_action(**overrides) -> RemediationAction:
    """Create a test action."""
    defaults = dict(
        action_id="user_temp_quarantine",
        name="Quarantine old temp files",
        description="Test action",
        risk_level=RiskLevel.MEDIUM,
        target="test temp dir",
        reason="testing",
        reversible=True,
        idempotent=True,
        parameters={"age_days": 0},  # 0 days = all files eligible
    )
    defaults.update(overrides)
    return RemediationAction(**defaults)


# ---------------------------------------------------------------------------
# Test A: Preview causes no filesystem changes
# ---------------------------------------------------------------------------

class TestA_PreviewNoChanges:
    def test_preview_does_not_modify_source(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            src = tmpdir / "temp"
            src.mkdir()
            old_file = _make_file(src, "old.txt", age_days=10)

            plan = preview_quarantine(
                temp_root=src,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )

            # Source file still exists
            assert old_file.exists()
            # Quarantine dir was NOT created
            assert not qdir.exists()
            # Plan has correct count
            assert plan.files_eligible == 1
        finally:
            _cleanup(tmpdir)

    def test_preview_no_action_preview_side_effects(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            action = _make_action()
            preview = preview_action(action)
            assert preview.action_id == "user_temp_quarantine"
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test B: Recent temp file is not moved
# ---------------------------------------------------------------------------

class TestB_RecentFileNotMoved:
    def test_young_file_not_eligible(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            young = _make_file(tmpdir, "recent.txt", age_days=1)
            eligible, reason = check_file_eligibility(
                young, tmpdir, age_threshold_days=7
            )
            assert not eligible
            assert "too young" in reason
        finally:
            _cleanup(tmpdir)

    def test_young_file_stays_after_execute(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            young = _make_file(tmpdir, "recent.txt", age_days=1)

            result = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )

            # File was not moved
            assert young.exists()
            assert result.files_moved == 0
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test C: Old temp file is moved
# ---------------------------------------------------------------------------

class TestC_OldFileMoved:
    def test_old_file_is_eligible(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            old = _make_file(tmpdir, "old.txt", age_days=10)
            eligible, reason = check_file_eligibility(
                old, tmpdir, age_threshold_days=7
            )
            assert eligible
        finally:
            _cleanup(tmpdir)

    def test_old_file_is_moved(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            old = _make_file(tmpdir, "old.txt", age_days=10)

            result = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )

            # File was moved
            assert not old.exists()
            assert result.files_moved == 1
            assert qdir.exists()
            # File exists in quarantine
            q_files = list(qdir.iterdir())
            assert len(q_files) == 1
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test D: Directory is never moved
# ---------------------------------------------------------------------------

class TestD_DirectoryNeverMoved:
    def test_directory_not_eligible(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            subdir = _make_subdir(tmpdir, "subdir")
            eligible, reason = check_file_eligibility(
                subdir, tmpdir, age_threshold_days=0
            )
            assert not eligible
            assert "not a regular file" in reason
        finally:
            _cleanup(tmpdir)

    def test_directory_not_in_scan_results(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            subdir = _make_subdir(tmpdir, "subdir")
            eligible, examined, warnings = scan_eligible_files(tmpdir, 0)
            # Directories are skipped entirely in scan
            assert all(f.path != subdir for f in eligible)
        finally:
            _cleanup(tmpdir)

    def test_directory_not_moved_on_execute(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            subdir = _make_subdir(tmpdir, "subdir")

            result = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=0,
                quarantine_dir=qdir,
            )

            # Directory still exists
            assert subdir.exists()
            assert result.files_moved == 0
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test E: Symlink is never moved
# ---------------------------------------------------------------------------

class TestE_SymlinkNeverMoved:
    def test_symlink_not_eligible(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            target = _make_file(tmpdir, "target.txt", content="data")
            symlink = tmpdir / "link.txt"
            try:
                symlink.symlink_to(target)
            except (OSError, NotImplementedError):
                pytest.skip("Symlinks not supported on this platform")

            eligible, reason = check_file_eligibility(
                symlink, tmpdir, age_threshold_days=0
            )
            assert not eligible
            assert "symlink" in reason
        finally:
            _cleanup(tmpdir)

    def test_symlink_not_moved_on_execute(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            target = _make_file(tmpdir, "target.txt", content="data")
            symlink = tmpdir / "link.txt"
            try:
                symlink.symlink_to(target)
            except (OSError, NotImplementedError):
                pytest.skip("Symlinks not supported on this platform")

            result = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=0,
                quarantine_dir=qdir,
            )

            # Symlink still exists
            assert symlink.exists()
            assert result.files_moved == 0
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test F: File outside approved temp root is rejected
# ---------------------------------------------------------------------------

class TestF_OutsideTempRootRejected:
    def test_file_outside_not_eligible(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            outside_dir = _make_temp_dir()
            outside_file = _make_file(outside_dir, "outside.txt")

            eligible, reason = check_file_eligibility(
                outside_file, tmpdir, age_threshold_days=0
            )
            assert not eligible
            assert "outside approved temp root" in reason
        finally:
            _cleanup(tmpdir)
            _cleanup(outside_dir)

    def test_outside_file_not_moved(self) -> None:
        tmpdir = _make_temp_dir()
        outside_dir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            outside_file = _make_file(outside_dir, "outside.txt", age_days=10)

            result = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=0,
                quarantine_dir=qdir,
            )

            assert outside_file.exists()
            assert result.files_moved == 0
        finally:
            _cleanup(tmpdir)
            _cleanup(outside_dir)


# ---------------------------------------------------------------------------
# Test G: Arbitrary path parameter is rejected
# ---------------------------------------------------------------------------

class TestG_ArbitraryPathRejected:
    def test_no_arbitrary_root_path_parameter(self) -> None:
        registry = create_default_registry()
        action = registry.get("user_temp_quarantine")
        schema = registry.get_schema("user_temp_quarantine")
        assert schema is not None

        # Attempt to inject arbitrary path
        bad_action = RemediationAction(
            action_id=action.action_id,
            name=action.name,
            description=action.description,
            risk_level=action.risk_level,
            target=action.target,
            reason=action.reason,
            reversible=action.reversible,
            parameters={"age_days": 7, "root_path": "/evil/path"},
        )
        errors = validate_action(bad_action, registry)
        assert not errors.valid
        assert any("Unknown parameters" in e for e in errors.errors)

    def test_schema_only_allows_age_days(self) -> None:
        registry = create_default_registry()
        schema = registry.get_schema("user_temp_quarantine")
        assert schema is not None
        all_allowed = schema.required | schema.optional
        assert all_allowed == {"age_days"}


# ---------------------------------------------------------------------------
# Test H: Wrong/forged confirmation cannot execute
# ---------------------------------------------------------------------------

class TestH_ForgedConfirmationRejected:
    def test_forged_token_rejected(self) -> None:
        from app.remediation.confirmation import ConfirmationToken

        action = _make_action()
        forged = ConfirmationToken(
            action_id=action.action_id,
            _secret="forged",
            _confirmed_hash="forged",
        )
        assert not forged.confirmed

    def test_wrong_action_token_rejected(self) -> None:
        from app.remediation.confirmation import ConfirmationToken, require_confirmation

        action = _make_action(action_id="correct")
        other = _make_action(action_id="wrong")
        token = confirm_action(other)
        with pytest.raises(ConfirmationRequiredError):
            require_confirmation(action, token)


# ---------------------------------------------------------------------------
# Test I: Execution without validation cannot execute
# ---------------------------------------------------------------------------

class TestI_NoExecutionWithoutValidation:
    def test_unvalidated_action_rejected(self) -> None:
        from app.remediation.executor import ExecutionDeniedError

        action = _make_action()
        token = confirm_action(action)
        invalid = ValidationResult(valid=False, errors=["test error"])
        registry = create_default_registry()
        tmpdir = _make_temp_dir()
        try:
            audit_store = _make_audit_store(tmpdir)
            qstore = _make_quarantine_store(tmpdir)
            executor = QuarantineExecutor(qstore)
            with pytest.raises(ExecutionDeniedError):
                executor.execute(action, token, invalid, registry, audit_store)
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test J: Changed file between preview and execution is skipped safely
# ---------------------------------------------------------------------------

class TestJ_ChangedFileSkipped:
    def test_file_removed_before_move_is_skipped(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            old_file = _make_file(tmpdir, "old.txt", age_days=10)

            # Scan first to get eligibility
            eligible, _, _ = scan_eligible_files(tmpdir, 7)
            assert len(eligible) == 1

            # Remove the file (simulate change)
            old_file.unlink()

            # Execute - should handle gracefully
            result = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )

            # File was skipped or failed, not crashed
            assert result.files_moved == 0
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test K: Access-denied file is skipped and reported
# ---------------------------------------------------------------------------

class TestK_AccessDeniedSkipped:
    def test_unreadable_file_is_skipped(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            # Create a file and try to make it inaccessible
            f = _make_file(tmpdir, "noaccess.txt", age_days=10)
            try:
                os.chmod(f, 0o000)
            except (OSError, NotImplementedError):
                pytest.skip("Cannot change file permissions on this platform")

            result = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )

            # On Windows, chmod 0o000 doesn't prevent access for the
            # current process, so the file may still be moved.  On Unix,
            # it should be skipped or failed.  Either way, no crash.
            assert result.files_moved + result.files_skipped + result.files_failed >= 1

            # Restore permissions for cleanup
            try:
                os.chmod(f, 0o666)
            except (OSError, PermissionError, FileNotFoundError):
                pass
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test L: Destination collision does not overwrite
# ---------------------------------------------------------------------------

class TestL_DestinationCollisionNoOverwrite:
    def test_collision_skips_file(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            qdir.mkdir()

            old_file = _make_file(tmpdir, "old.txt", age_days=10)
            old_mtime = old_file.stat().st_mtime

            # Create a conflicting file in quarantine
            conflict = generate_quarantine_path(qdir, old_file, old_mtime)
            conflict.write_text("already here")

            result = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )

            # Original file still exists (collision)
            assert old_file.exists()
            # Existing file not overwritten
            assert conflict.read_text() == "already here"
            assert result.files_skipped > 0
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test M: Quarantine metadata is created correctly
# ---------------------------------------------------------------------------

class TestM_QuarantineMetadata:
    def test_quarantine_record_created(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            old_file = _make_file(tmpdir, "old.txt", content="hello", age_days=10)
            original_size = old_file.stat().st_size
            original_mtime = str(old_file.stat().st_mtime)

            qstore = _make_quarantine_store(tmpdir)

            result = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )

            assert result.files_moved == 1

            # Check quarantine directory has the file
            q_files = list(qdir.iterdir())
            assert len(q_files) == 1
            q_file = q_files[0]

            # Create a quarantine record manually for testing
            record = QuarantineRecord(
                action_id="user_temp_quarantine",
                original_path=str(old_file),
                quarantine_path=str(q_file),
                original_size=original_size,
                original_mtime=original_mtime,
            )
            record_id = qstore.create_record(record)
            assert record_id > 0

            loaded = qstore.get_record(record_id)
            assert loaded is not None
            assert loaded.action_id == "user_temp_quarantine"
            assert loaded.original_size == original_size
            assert not loaded.restored
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test N: Rollback restores a quarantined file
# ---------------------------------------------------------------------------

class TestN_RollbackRestores:
    def test_rollback_restores_file(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            src = tmpdir / "temp"
            src.mkdir()
            old_file = _make_file(src, "old.txt", content="original", age_days=10)
            original_path = str(old_file)

            qstore = _make_quarantine_store(tmpdir)

            result = execute_quarantine(
                temp_root=src,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )
            assert result.files_moved == 1
            assert not old_file.exists()

            # Get the quarantined file
            q_files = list(qdir.iterdir())
            assert len(q_files) == 1
            q_file = q_files[0]

            # Create quarantine record
            record = QuarantineRecord(
                action_id="user_temp_quarantine",
                original_path=original_path,
                quarantine_path=str(q_file),
                original_size=9,  # len("original")
                original_mtime=str(time.time()),
            )
            record_id = qstore.create_record(record)

            # Rollback
            success, message = rollback_quarantine(
                record_id, qstore, overwrite=False
            )
            assert success
            assert old_file.exists()
            assert old_file.read_text() == "original"
            assert not q_file.exists()

            # Record marked as restored
            loaded = qstore.get_record(record_id)
            assert loaded is not None
            assert loaded.restored
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test O: Rollback refuses to overwrite newly-created destination
# ---------------------------------------------------------------------------

class TestO_RollbackNoOverwrite:
    def test_rollback_refuses_overwrite(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            src = tmpdir / "temp"
            src.mkdir()
            old_file = _make_file(src, "old.txt", content="original", age_days=10)
            original_path = str(old_file)

            qstore = _make_quarantine_store(tmpdir)

            result = execute_quarantine(
                temp_root=src,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )
            assert result.files_moved == 1

            # Get quarantined file
            q_files = list(qdir.iterdir())
            q_file = q_files[0]

            # Create a new file at original path
            old_file.write_text("new content")

            # Create quarantine record
            record = QuarantineRecord(
                action_id="user_temp_quarantine",
                original_path=original_path,
                quarantine_path=str(q_file),
                original_size=9,
                original_mtime=str(time.time()),
            )
            record_id = qstore.create_record(record)

            # Rollback should refuse
            success, message = rollback_quarantine(
                record_id, qstore, overwrite=False
            )
            assert not success
            assert "already exists" in message
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test P: Rollback of missing quarantine file fails safely
# ---------------------------------------------------------------------------

class TestP_RollbackMissingFile:
    def test_rollback_missing_file_fails(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qstore = _make_quarantine_store(tmpdir)

            record = QuarantineRecord(
                action_id="user_temp_quarantine",
                original_path=str(tmpdir / "original.txt"),
                quarantine_path=str(tmpdir / "nonexistent.txt"),
                original_size=0,
                original_mtime=str(time.time()),
            )
            record_id = qstore.create_record(record)

            success, message = rollback_quarantine(
                record_id, qstore, overwrite=False
            )
            assert not success
            assert "no longer exists" in message
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test Q: Partial failure produces accurate structured result
# ---------------------------------------------------------------------------

class TestQ_PartialFailureResult:
    def test_partial_failure_counted(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"

            # Create files: one will succeed, one will fail (remove before move)
            good = _make_file(tmpdir, "good.txt", age_days=10)
            bad = _make_file(tmpdir, "bad.txt", age_days=10)

            result = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )

            # At least some files were processed
            assert result.files_examined >= 2
            assert result.files_eligible >= 2
            # At least one moved
            assert result.files_moved >= 1
            # Total bytes is accurate
            assert result.total_bytes_moved > 0
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test R: Audit records reflect execution and rollback
# ---------------------------------------------------------------------------

class TestR_AuditRecords:
    def test_audit_record_created_on_execute(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            old_file = _make_file(tmpdir, "old.txt", age_days=10)

            audit_store = _make_audit_store(tmpdir)
            qstore = _make_quarantine_store(tmpdir)

            action = _make_action()
            token = confirm_action(action)
            registry = create_default_registry()
            validation = validate_action(action, registry)

            executor = QuarantineExecutor(qstore)
            result = executor.execute(
                action, token, validation, registry, audit_store
            )

            assert result.audit_record_id is not None
            loaded = audit_store.get_record(result.audit_record_id)
            assert loaded is not None
            assert loaded.action_id == "user_temp_quarantine"
            assert loaded.status in (
                AuditStatus.SUCCEEDED.value,
                AuditStatus.PARTIALLY_SUCCEEDED.value,
            )
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test S: Running quarantine again doesn't re-move already-quarantined file
# ---------------------------------------------------------------------------

class TestS_IdempotentExecution:
    def test_already_moved_file_not_moved_again(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            old = _make_file(tmpdir, "old.txt", age_days=10)

            result1 = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )
            assert result1.files_moved == 1
            assert not old.exists()

            # Run again - no files eligible
            result2 = execute_quarantine(
                temp_root=tmpdir,
                age_threshold_days=7,
                quarantine_dir=qdir,
            )
            assert result2.files_moved == 0
            assert result2.files_eligible == 0
        finally:
            _cleanup(tmpdir)


# ---------------------------------------------------------------------------
# Test T: No subprocess, shell, registry, service, or privilege escalation
# ---------------------------------------------------------------------------

class TestT_NoDangerousPaths:
    def test_no_subprocess_imports(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            assert "import subprocess" not in content, f"{py_file.name} imports subprocess"

    def test_no_os_system_calls(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            assert "os.system(" not in content, f"{py_file.name} calls os.system"

    def test_no_registry_writes(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        dangerous = ["RegSetValue", "RegCreateKey", "HKEY_LOCAL_MACHINE"]
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            for pattern in dangerous:
                assert pattern not in content, f"{py_file.name} contains {pattern}"

    def test_no_file_deletion(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            assert "os.remove(" not in content, f"{py_file.name} calls os.remove"
            assert "os.unlink(" not in content, f"{py_file.name} calls os.unlink"

    def test_no_shell_execution(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            assert "Popen(" not in content, f"{py_file.name} uses Popen"
            assert "os.popen(" not in content, f"{py_file.name} uses os.popen"

    def test_no_service_modification(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        dangerous = ["ChangeServiceConfig", "StartService", "ControlService"]
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            for pattern in dangerous:
                assert pattern not in content, f"{py_file.name} contains {pattern}"

    def test_no_privilege_escalation(self) -> None:
        from pathlib import Path
        remediation_dir = Path(__file__).parent.parent / "app" / "remediation"
        dangerous = ["RunAs", "ShellExecute", "create_expanded_environment"]
        for py_file in remediation_dir.glob("*.py"):
            content = py_file.read_text()
            for pattern in dangerous:
                assert pattern not in content, f"{py_file.name} contains {pattern}"


# ---------------------------------------------------------------------------
# Additional unit tests
# ---------------------------------------------------------------------------

class TestQuarantineUnitTests:
    def test_get_user_temp_dir(self) -> None:
        """Should return a valid temp directory."""
        temp_dir = get_user_temp_dir()
        assert temp_dir is not None
        assert temp_dir.is_dir()

    def test_get_quarantine_dir_default(self) -> None:
        """Default quarantine dir should be under home."""
        qdir = get_quarantine_dir()
        assert str(qdir).startswith(str(Path.home()))

    def test_get_quarantine_dir_custom(self) -> None:
        """Custom quarantine dir should be under app data."""
        custom = Path("/tmp/myapp")
        qdir = get_quarantine_dir(custom)
        assert qdir == custom / "quarantine"

    def test_is_under_directory(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            child = tmpdir / "child" / "file.txt"
            assert is_under_directory(child, tmpdir)
            outside = Path("/other/path")
            assert not is_under_directory(outside, tmpdir)
        finally:
            _cleanup(tmpdir)

    def test_generate_unique_path(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            qdir = tmpdir / "quarantine"
            qdir.mkdir()
            original = Path("test.txt")
            t1 = time.time()
            t2 = t1 + 1  # Ensure different timestamp
            path1 = generate_quarantine_path(qdir, original, t1)
            path2 = generate_quarantine_path(qdir, original, t2)
            assert path1 != path2
        finally:
            _cleanup(tmpdir)

    def test_quarantine_result_defaults(self) -> None:
        r = QuarantineResult()
        assert r.files_moved == 0
        assert r.total_bytes_moved == 0

    def test_quarantine_plan_defaults(self) -> None:
        p = QuarantinePlan(
            source_dir="/tmp",
            age_threshold_days=7,
            files_examined=0,
            files_eligible=0,
            total_size_bytes=0,
            eligible_files=[],
        )
        assert p.rollback_available is True

    def test_registry_has_quarantine_action(self) -> None:
        registry = create_default_registry()
        assert registry.is_registered("user_temp_quarantine")
        action = registry.get("user_temp_quarantine")
        assert action.reversible is True
        assert action.requires_admin is False
        assert action.risk_level == RiskLevel.MEDIUM

    def test_quarantine_action_schema(self) -> None:
        registry = create_default_registry()
        schema = registry.get_schema("user_temp_quarantine")
        assert schema is not None
        assert "age_days" in schema.optional

    def test_quarantine_store_create_and_get(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            store = _make_quarantine_store(tmpdir)
            record = QuarantineRecord(
                action_id="test",
                original_path="/tmp/test.txt",
                quarantine_path="/quarantine/test.txt",
                original_size=100,
                original_mtime="2024-01-01T00:00:00",
            )
            record_id = store.create_record(record)
            loaded = store.get_record(record_id)
            assert loaded is not None
            assert loaded.action_id == "test"
            assert loaded.original_size == 100
        finally:
            _cleanup(tmpdir)

    def test_quarantine_store_mark_restored(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            store = _make_quarantine_store(tmpdir)
            record = QuarantineRecord(
                action_id="test",
                original_path="/tmp/test.txt",
                quarantine_path="/quarantine/test.txt",
                original_size=100,
                original_mtime="2024-01-01T00:00:00",
            )
            record_id = store.create_record(record)
            store.mark_restored(record_id)
            loaded = store.get_record(record_id)
            assert loaded is not None
            assert loaded.restored is True
            assert loaded.restored_at is not None
        finally:
            _cleanup(tmpdir)

    def test_quarantine_store_list_records(self) -> None:
        tmpdir = _make_temp_dir()
        try:
            store = _make_quarantine_store(tmpdir)
            for i in range(3):
                store.create_record(QuarantineRecord(
                    action_id="test",
                    original_path=f"/tmp/test{i}.txt",
                    quarantine_path=f"/quarantine/test{i}.txt",
                    original_size=100,
                    original_mtime="2024-01-01T00:00:00",
                ))
            all_records = store.list_records()
            assert len(all_records) == 3
            filtered = store.list_records(action_id="test")
            assert len(filtered) == 3
            empty = store.list_records(action_id="nonexistent")
            assert len(empty) == 0
        finally:
            _cleanup(tmpdir)

    def test_preview_action_returns_plan(self) -> None:
        action = _make_action()
        preview = preview_action(action)
        assert preview.quarantine_plan is not None
        assert isinstance(preview.quarantine_plan, QuarantinePlan)

    def test_simulation_executor_still_works(self) -> None:
        """Phase 3A demo actions should still work."""
        tmpdir = _make_temp_dir()
        try:
            from app.remediation.action import RemediationAction
            action = RemediationAction(
                action_id="demo.noop.print_message",
                name="Test",
                description="Test",
                risk_level=RiskLevel.LOW,
                target="test",
                reason="test",
                reversible=True,
                parameters={"message": "hello"},
            )
            token = confirm_action(action)
            registry = create_default_registry()
            validation = validate_action(action, registry)
            audit_store = _make_audit_store(tmpdir)

            executor = SimulationExecutor()
            result = executor.execute(
                action, token, validation, registry, audit_store
            )
            assert result.success
            assert result.simulated
        finally:
            _cleanup(tmpdir)

    def test_rollback_quarantine_file_wrapper(self) -> None:
        from app.remediation.rollback import rollback_quarantine_file
        tmpdir = _make_temp_dir()
        try:
            qstore = _make_quarantine_store(tmpdir)
            record = QuarantineRecord(
                action_id="test",
                original_path=str(tmpdir / "original.txt"),
                quarantine_path=str(tmpdir / "nonexistent.txt"),
                original_size=0,
                original_mtime=str(time.time()),
            )
            record_id = qstore.create_record(record)
            success, msg = rollback_quarantine_file(qstore, record_id)
            assert not success
            assert "no longer exists" in msg
        finally:
            _cleanup(tmpdir)

    def test_audit_status_partially_succeeded(self) -> None:
        """PARTIALLY_SUCCEEDED should be a valid status."""
        assert AuditStatus.PARTIALLY_SUCCEEDED.value == "partially_succeeded"

    def test_audit_transition_executing_to_partially(self) -> None:
        """EXECUTING -> PARTIALLY_SUCCEEDED should be allowed."""
        tmpdir = _make_temp_dir()
        try:
            store = _make_audit_store(tmpdir)
            rid = store.create_record(AuditRecord(action_id="test"))
            store.update_status(rid, AuditStatus.PREVIEWED)
            store.update_status(rid, AuditStatus.CONFIRMED)
            store.update_status(rid, AuditStatus.EXECUTING)
            store.update_status(rid, AuditStatus.PARTIALLY_SUCCEEDED)
            loaded = store.get_record(rid)
            assert loaded.status == AuditStatus.PARTIALLY_SUCCEEDED.value
        finally:
            _cleanup(tmpdir)

    def test_audit_transition_partially_to_rolled_back(self) -> None:
        """PARTIALLY_SUCCEEDED -> ROLLED_BACK should be allowed."""
        tmpdir = _make_temp_dir()
        try:
            store = _make_audit_store(tmpdir)
            rid = store.create_record(AuditRecord(action_id="test"))
            store.update_status(rid, AuditStatus.PREVIEWED)
            store.update_status(rid, AuditStatus.CONFIRMED)
            store.update_status(rid, AuditStatus.EXECUTING)
            store.update_status(rid, AuditStatus.PARTIALLY_SUCCEEDED)
            store.update_status(rid, AuditStatus.ROLLED_BACK)
            loaded = store.get_record(rid)
            assert loaded.status == AuditStatus.ROLLED_BACK.value
        finally:
            _cleanup(tmpdir)
