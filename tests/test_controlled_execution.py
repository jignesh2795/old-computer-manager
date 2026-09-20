"""Comprehensive tests for Phase 11D: Controlled Execution.

Tests the ControlledExecutionService, authorization checks, TOCTOU revalidation,
double execution prevention, audit lifecycle, and verifies that only production
actions may execute.
"""

from __future__ import annotations

import ast
import os
import threading
import time

import pytest

from app.remediation.candidates import (
    ActionCandidate,
    CandidateStatus,
    EvidenceSource,
    EvidenceSourceType,
)
from app.remediation.preview import (
    Preview,
    PreviewBuilder,
    PreviewStatus,
    build_preview,
)
from app.remediation.confirmation_service import (
    ConfirmationService,
    ConfirmationStore,
)
from app.remediation.controlled_execution import (
    ControlledExecutionService,
    ControlledExecutionResult,
    ExecutionStore,
    ExecutionStatus,
    ExecutionDeniedError,
    NotProductionActionError,
    DoubleExecutionError,
    StalePreviewError,
    PreviewMismatchError,
    ActionVersionMismatchError,
    RevalidationFailedError,
    PRODUCTION_ACTIONS,
    revalidate_preview_targets,
    get_execution_service,
)
from app.remediation.catalog import get_catalog_entry
from app.remediation.action import ImplementationStatus, EligibilityStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_candidate(
    status: CandidateStatus = CandidateStatus.AVAILABLE,
    action_id: str = "disk.cleanup_temp",
    candidate_id: str = "available.disk.cleanup_temp",
) -> ActionCandidate:
    """Create a test ActionCandidate."""
    return ActionCandidate(
        candidate_id=candidate_id,
        action_id=action_id,
        title="Cleanup temp files",
        reason="Test candidate",
        status=status,
        evidence=[
            EvidenceSource(
                source_type=EvidenceSourceType.FILE_ANALYSIS,
                source_id="temp",
                observation="temp files found",
            )
        ],
        risk_level="low",
        reversible=True,
    )


def _make_ready_preview(candidate: ActionCandidate | None = None) -> Preview:
    """Create a READY preview for testing."""
    if candidate is None:
        candidate = _make_candidate()
    builder = PreviewBuilder()
    return builder.build_preview(candidate)


# ---------------------------------------------------------------------------
# A. Production action allowlist
# ---------------------------------------------------------------------------
class TestProductionActions:
    def test_production_actions_are_frozen(self) -> None:
        assert isinstance(PRODUCTION_ACTIONS, frozenset)

    def test_only_two_production_actions(self) -> None:
        assert len(PRODUCTION_ACTIONS) == 2
        assert "user_temp_quarantine" in PRODUCTION_ACTIONS
        assert "disk.cleanup_temp" in PRODUCTION_ACTIONS

    def test_production_actions_are_implemented(self) -> None:
        for action_id in PRODUCTION_ACTIONS:
            entry = get_catalog_entry(action_id)
            assert entry is not None
            assert entry.implementation_status == ImplementationStatus.IMPLEMENTED

    def test_production_actions_are_eligible(self) -> None:
        for action_id in PRODUCTION_ACTIONS:
            entry = get_catalog_entry(action_id)
            assert entry is not None
            assert entry.eligibility == EligibilityStatus.ELIGIBLE


# ---------------------------------------------------------------------------
# B. ExecutionStore
# ---------------------------------------------------------------------------
class TestExecutionStore:
    def test_consume_confirmation(self) -> None:
        store = ExecutionStore()
        assert store.consume_confirmation("conf:1") is True
        assert store.is_confirmation_consumed("conf:1") is True

    def test_double_consume_rejected(self) -> None:
        store = ExecutionStore()
        assert store.consume_confirmation("conf:1") is True
        assert store.consume_confirmation("conf:1") is False

    def test_different_confirmations_independent(self) -> None:
        store = ExecutionStore()
        assert store.consume_confirmation("conf:1") is True
        assert store.consume_confirmation("conf:2") is True
        assert store.is_confirmation_consumed("conf:1") is True
        assert store.is_confirmation_consumed("conf:2") is True


# ---------------------------------------------------------------------------
# C. Authorization checks
# ---------------------------------------------------------------------------
class TestAuthorizationChecks:
    def test_execute_production_action(self) -> None:
        """Available candidate + READY preview + valid confirmation should succeed."""
        conf_store = ConfirmationStore()
        conf_service = ConfirmationService(store=conf_store)
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store, confirmation_store=conf_store)

        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)
        record = conf_service.confirm(candidate, preview)

        result = service.execute(candidate, preview, record.confirmation_id)
        assert result.execution_id.startswith("exec:")
        assert result.status in (ExecutionStatus.SUCCEEDED.value, ExecutionStatus.PARTIALLY_SUCCEEDED.value, ExecutionStatus.FAILED.value)

    def test_non_production_action_rejected(self) -> None:
        """Non-production action cannot execute."""
        conf_store = ConfirmationStore()
        conf_service = ConfirmationService(store=conf_store)
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store, confirmation_store=conf_store)

        candidate = _make_candidate(
            CandidateStatus.AVAILABLE,
            action_id="demo.noop.print_message",
            candidate_id="available.demo.noop",
        )
        preview = _make_ready_preview(candidate)
        record = conf_service.confirm(candidate, preview)

        with pytest.raises(NotProductionActionError):
            service.execute(candidate, preview, record.confirmation_id)

    def test_proposed_action_rejected(self) -> None:
        """Proposed action cannot execute."""
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store)

        candidate = _make_candidate(
            CandidateStatus.PROPOSED,
            action_id="disk.cleanup_logs",
            candidate_id="proposed.disk.cleanup_logs",
        )
        preview = _make_ready_preview(candidate)

        with pytest.raises(ExecutionDeniedError):
            service.execute(candidate, preview, "fake_confirmation")

    def test_blocked_action_rejected(self) -> None:
        """Blocked action cannot execute."""
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store)

        candidate = _make_candidate(
            CandidateStatus.BLOCKED,
            action_id="startup.disable_entry",
            candidate_id="blocked.startup.disable_entry",
        )
        preview = _make_ready_preview(candidate)

        with pytest.raises(ExecutionDeniedError):
            service.execute(candidate, preview, "fake_confirmation")

    def test_stale_preview_rejected(self) -> None:
        """STALE preview cannot execute."""
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store)

        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        stale_preview = Preview(
            preview_id="preview:stale",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at="2026-01-01T00:00:00",
            status=PreviewStatus.STALE,
            title="Stale",
            summary="Stale",
            target="Unknown",
            affected_count=0,
            affected_bytes=0,
        )

        with pytest.raises(StalePreviewError):
            service.execute(candidate, stale_preview, "fake_confirmation")

    def test_preview_mismatch_rejected(self) -> None:
        """Preview with wrong candidate_id cannot execute."""
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store)

        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        mismatched_preview = Preview(
            preview_id="preview:wrong",
            candidate_id="wrong_candidate",
            action_id=candidate.action_id,
            generated_at="2026-01-01T00:00:00",
            status=PreviewStatus.READY,
            title="Wrong",
            summary="Wrong",
            target="Wrong",
            affected_count=0,
            affected_bytes=0,
        )

        with pytest.raises(PreviewMismatchError):
            service.execute(candidate, mismatched_preview, "fake_confirmation")

    def test_consumed_token_rejected(self) -> None:
        """Consumed confirmation token cannot be reused."""
        conf_store = ConfirmationStore()
        conf_service = ConfirmationService(store=conf_store)
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store, confirmation_store=conf_store)

        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)
        record = conf_service.confirm(candidate, preview)

        # First execution
        service.execute(candidate, preview, record.confirmation_id)

        # Second execution with same token should fail
        with pytest.raises(DoubleExecutionError):
            service.execute(candidate, preview, record.confirmation_id)

    def test_invalid_confirmation_rejected(self) -> None:
        """Non-existent confirmation cannot execute."""
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store)

        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)

        with pytest.raises(ExecutionDeniedError):
            service.execute(candidate, preview, "nonexistent_confirmation")


# ---------------------------------------------------------------------------
# D. Double execution prevention (concurrent)
# ---------------------------------------------------------------------------
class TestDoubleExecutionPrevention:
    def test_concurrent_execution_prevented(self) -> None:
        """Two concurrent attempts with same confirmation must not both execute."""
        conf_store = ConfirmationStore()
        conf_service = ConfirmationService(store=conf_store)
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store, confirmation_store=conf_store)

        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)
        record = conf_service.confirm(candidate, preview)

        results: list[str] = []
        errors: list[str] = []

        def execute_attempt() -> None:
            try:
                result = service.execute(candidate, preview, record.confirmation_id)
                results.append(result.status)
            except DoubleExecutionError:
                errors.append("double_execution")
            except Exception as e:
                errors.append(str(e))

        threads = [
            threading.Thread(target=execute_attempt),
            threading.Thread(target=execute_attempt),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        # Exactly one should succeed, one should fail
        assert len(results) + len(errors) == 2
        assert "double_execution" in errors
        assert len(results) == 1


# ---------------------------------------------------------------------------
# E. Confirmation token consumption
# ---------------------------------------------------------------------------
class TestTokenConsumption:
    def test_token_consumed_after_execution(self) -> None:
        """Confirmation token is consumed after execution."""
        conf_store = ConfirmationStore()
        conf_service = ConfirmationService(store=conf_store)
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store, confirmation_store=conf_store)

        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)
        record = conf_service.confirm(candidate, preview)

        assert exec_store.is_confirmation_consumed(record.confirmation_id) is False
        service.execute(candidate, preview, record.confirmation_id)
        assert exec_store.is_confirmation_consumed(record.confirmation_id) is True

    def test_token_not_reusable_after_failure(self) -> None:
        """Consumed token cannot be reused even if execution failed."""
        conf_store = ConfirmationStore()
        conf_service = ConfirmationService(store=conf_store)
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store, confirmation_store=conf_store)

        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)
        record = conf_service.confirm(candidate, preview)

        # Execute (may succeed or fail depending on filesystem)
        service.execute(candidate, preview, record.confirmation_id)

        # Token is consumed regardless of execution outcome
        assert exec_store.is_confirmation_consumed(record.confirmation_id) is True

        # Cannot reuse
        with pytest.raises(DoubleExecutionError):
            service.execute(candidate, preview, record.confirmation_id)


# ---------------------------------------------------------------------------
# F. Execution result
# ---------------------------------------------------------------------------
class TestExecutionResult:
    def test_result_has_required_fields(self) -> None:
        """ExecutionResult contains all required traceability fields."""
        conf_store = ConfirmationStore()
        conf_service = ConfirmationService(store=conf_store)
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store, confirmation_store=conf_store)

        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)
        record = conf_service.confirm(candidate, preview)

        result = service.execute(candidate, preview, record.confirmation_id)

        assert result.execution_id.startswith("exec:")
        assert result.action_id == candidate.action_id
        assert result.action_version == "1"
        assert result.candidate_id == candidate.candidate_id
        assert result.confirmation_id == record.confirmation_id
        assert result.started_at != ""
        assert result.completed_at != ""
        assert result.status in [s.value for s in ExecutionStatus]
        assert isinstance(result.files_examined, int)
        assert isinstance(result.files_moved, int)
        assert isinstance(result.files_skipped, int)
        assert isinstance(result.files_failed, int)
        assert isinstance(result.bytes_moved, int)
        assert isinstance(result.quarantine_record_ids, list)
        assert isinstance(result.result_summary, str)
        assert isinstance(result.errors, list)
        assert isinstance(result.rollback_available, bool)

    def test_result_stored_in_store(self) -> None:
        """ExecutionResult is stored in the ExecutionStore."""
        conf_store = ConfirmationStore()
        conf_service = ConfirmationService(store=conf_store)
        exec_store = ExecutionStore()
        service = ControlledExecutionService(store=exec_store, confirmation_store=conf_store)

        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)
        record = conf_service.confirm(candidate, preview)

        result = service.execute(candidate, preview, record.confirmation_id)
        assert exec_store.count() == 1
        assert exec_store.get_record(result.execution_id) is not None


# ---------------------------------------------------------------------------
# G. TOCTOU revalidation
# ---------------------------------------------------------------------------
class TestTOCTOURevalidation:
    def test_revalidate_empty_items(self) -> None:
        """Empty preview items should pass revalidation."""
        valid, errors = revalidate_preview_targets([], "/tmp")
        assert valid is True
        assert errors == []

    def test_revalidate_nonexistent_file(self) -> None:
        """Non-existent file should fail revalidation."""
        items = [{"path": "/nonexistent/path/file.txt", "size_bytes": 100}]
        valid, errors = revalidate_preview_targets(items, "/tmp")
        assert valid is False
        assert len(errors) > 0

    @pytest.mark.skipif(
        os.name == "nt",
        reason="Symlink creation requires elevated privileges on Windows"
    )
    def test_revalidate_symlink(self) -> None:
        """Symlink should fail revalidation."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a symlink
            target = os.path.join(tmpdir, "target.txt")
            link = os.path.join(tmpdir, "link.txt")
            with open(target, "w") as f:
                f.write("test")
            os.symlink(target, link)

            items = [{"path": link, "size_bytes": 4}]
            valid, errors = revalidate_preview_targets(items, tmpdir)
            assert valid is False
            assert any("symlink" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# H. No execution authority for AI
# ---------------------------------------------------------------------------
class TestAINonExecution:
    def test_no_ai_import_in_controlled_execution(self) -> None:
        """controlled_execution.py must not import AI modules."""
        path = os.path.join("app", "remediation", "controlled_execution.py")
        with open(path) as f:
            content = f.read()
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "ai" not in node.module.lower()

    def test_no_subprocess_import(self) -> None:
        path = os.path.join("app", "remediation", "controlled_execution.py")
        with open(path) as f:
            content = f.read()
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert "subprocess" not in a.name.lower()
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "subprocess" not in node.module.lower()


# ---------------------------------------------------------------------------
# I. Only production actions executable
# ---------------------------------------------------------------------------
class TestOnlyProductionExecutable:
    @pytest.mark.parametrize("action_id", list(PRODUCTION_ACTIONS))
    def test_production_action_allowed(self, action_id: str) -> None:
        """Production actions are in the allowlist."""
        assert action_id in PRODUCTION_ACTIONS
        entry = get_catalog_entry(action_id)
        assert entry is not None
        assert entry.implementation_status == ImplementationStatus.IMPLEMENTED

    def test_demo_action_not_in_production(self) -> None:
        """Demo actions are NOT in production allowlist."""
        assert "demo.noop.print_message" not in PRODUCTION_ACTIONS
        assert "demo.noop.report_status" not in PRODUCTION_ACTIONS

    def test_blocked_actions_not_in_production(self) -> None:
        """Blocked actions are NOT in production allowlist."""
        assert "startup.disable_entry" not in PRODUCTION_ACTIONS
        assert "service.stop_temporary" not in PRODUCTION_ACTIONS

    def test_proposed_actions_not_in_production(self) -> None:
        """Proposed actions are NOT in production allowlist."""
        assert "disk.cleanup_logs" not in PRODUCTION_ACTIONS
        assert "browser.cache_clear" not in PRODUCTION_ACTIONS


# ---------------------------------------------------------------------------
# J. No arbitrary parameters
# ---------------------------------------------------------------------------
class TestNoArbitraryParameters:
    def test_cli_has_no_force_flags(self) -> None:
        """execute-candidate CLI has no --yes, --force, --path, --root, --command."""
        import subprocess
        result = subprocess.run(
            ["python", "-m", "app.cli", "actions", "execute-candidate", "--help"],
            capture_output=True,
            text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        output = result.stdout + result.stderr
        assert "--yes" not in output.lower()
        assert "--force" not in output.lower()
        assert "--path" not in output.lower()
        assert "--root" not in output.lower()
        assert "--command" not in output.lower()


# ---------------------------------------------------------------------------
# K. Module-level convenience
# ---------------------------------------------------------------------------
class TestModuleLevelConvenience:
    def test_get_execution_service_returns_same_instance(self) -> None:
        s1 = get_execution_service()
        s2 = get_execution_service()
        assert s1 is s2


# ---------------------------------------------------------------------------
# L. ExecutionStatus enum
# ---------------------------------------------------------------------------
class TestExecutionStatus:
    def test_statuses(self) -> None:
        statuses = [s.value for s in ExecutionStatus]
        assert "succeeded" in statuses
        assert "partially_succeeded" in statuses
        assert "failed" in statuses
        assert "cancelled" in statuses
        assert "rolled_back" in statuses


# ---------------------------------------------------------------------------
# M. ControlledExecutionResult immutability
# ---------------------------------------------------------------------------
class TestResultImmutability:
    def test_result_is_frozen(self) -> None:
        result = ControlledExecutionResult(
            execution_id="exec:1",
            action_id="disk.cleanup_temp",
            action_version="1",
            candidate_id="c1",
            confirmation_id="conf:1",
        )
        with pytest.raises(AttributeError):
            result.execution_id = "hacked"  # type: ignore[misc]
