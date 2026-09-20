"""Comprehensive tests for Phase 11C: Explicit Human Confirmation.

Tests the ConfirmationService, ConfirmationRecord, ConfirmationStore,
API endpoint, CLI command, and verifies that NO execution authority
is granted by the confirmation subsystem alone.
"""

from __future__ import annotations

import ast
import os

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
    ConfirmationRecord,
    ConfirmationStore,
    ConfirmationError,
    StalePreviewError,
    InsufficientEvidenceError,
    BlockedCandidateError,
    ProposedCandidateError,
    InvalidPreviewStatusError,
    PreviewMismatchError,
    ConfirmationAlreadyUsedError,
    confirm_candidate,
    get_confirmation_service,
)


# ---------------------------------------------------------------------------
# Helper
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
# A. ConfirmationRecord model
# ---------------------------------------------------------------------------
class TestConfirmationRecord:
    def test_record_is_frozen(self) -> None:
        record = ConfirmationRecord(
            confirmation_id="conf:1",
            candidate_id="c1",
            action_id="disk.cleanup_temp",
            preview_id="preview:c1",
            preview_fingerprint="abc123",
            confirmed_at="2026-01-01T00:00:00",
            confirmation_token_secret="secret123",
        )
        with pytest.raises(AttributeError):
            record.consumed = True  # type: ignore[misc]

    def test_record_is_valid_for_matching(self) -> None:
        record = ConfirmationRecord(
            confirmation_id="conf:1",
            candidate_id="c1",
            action_id="disk.cleanup_temp",
            preview_id="preview:c1",
            preview_fingerprint="abc123",
            confirmed_at="2026-01-01T00:00:00",
            confirmation_token_secret="secret123",
        )
        assert record.is_valid_for("c1", "abc123") is True

    def test_record_is_valid_for_wrong_candidate(self) -> None:
        record = ConfirmationRecord(
            confirmation_id="conf:1",
            candidate_id="c1",
            action_id="disk.cleanup_temp",
            preview_id="preview:c1",
            preview_fingerprint="abc123",
            confirmed_at="2026-01-01T00:00:00",
            confirmation_token_secret="secret123",
        )
        assert record.is_valid_for("c2", "abc123") is False

    def test_record_is_valid_for_wrong_fingerprint(self) -> None:
        record = ConfirmationRecord(
            confirmation_id="conf:1",
            candidate_id="c1",
            action_id="disk.cleanup_temp",
            preview_id="preview:c1",
            preview_fingerprint="abc123",
            confirmed_at="2026-01-01T00:00:00",
            confirmation_token_secret="secret123",
        )
        assert record.is_valid_for("c1", "wrong_fingerprint") is False

    def test_consumed_record_is_invalid(self) -> None:
        record = ConfirmationRecord(
            confirmation_id="conf:1",
            candidate_id="c1",
            action_id="disk.cleanup_temp",
            preview_id="preview:c1",
            preview_fingerprint="abc123",
            confirmed_at="2026-01-01T00:00:00",
            confirmation_token_secret="secret123",
            consumed=True,
        )
        assert record.is_valid_for("c1", "abc123") is False


# ---------------------------------------------------------------------------
# B. ConfirmationStore
# ---------------------------------------------------------------------------
class TestConfirmationStore:
    def test_add_and_get(self) -> None:
        store = ConfirmationStore()
        record = ConfirmationRecord(
            confirmation_id="conf:1",
            candidate_id="c1",
            action_id="disk.cleanup_temp",
            preview_id="preview:c1",
            preview_fingerprint="abc123",
            confirmed_at="2026-01-01T00:00:00",
            confirmation_token_secret="secret123",
        )
        store.add(record)
        assert store.get("conf:1") is record
        assert store.get("nonexistent") is None

    def test_get_for_candidate(self) -> None:
        store = ConfirmationStore()
        r1 = ConfirmationRecord(
            confirmation_id="conf:1", candidate_id="c1", action_id="a",
            preview_id="p1", preview_fingerprint="f1", confirmed_at="t1",
            confirmation_token_secret="s1",
        )
        r2 = ConfirmationRecord(
            confirmation_id="conf:2", candidate_id="c1", action_id="a",
            preview_id="p2", preview_fingerprint="f2", confirmed_at="t2",
            confirmation_token_secret="s2",
        )
        r3 = ConfirmationRecord(
            confirmation_id="conf:3", candidate_id="c2", action_id="a",
            preview_id="p3", preview_fingerprint="f3", confirmed_at="t3",
            confirmation_token_secret="s3",
        )
        store.add(r1)
        store.add(r2)
        store.add(r3)
        assert len(store.get_for_candidate("c1")) == 2
        assert len(store.get_for_candidate("c2")) == 1
        assert len(store.get_for_candidate("c3")) == 0

    def test_mark_consumed(self) -> None:
        store = ConfirmationStore()
        record = ConfirmationRecord(
            confirmation_id="conf:1", candidate_id="c1", action_id="a",
            preview_id="p1", preview_fingerprint="f1", confirmed_at="t1",
            confirmation_token_secret="s1",
        )
        store.add(record)
        assert store.get("conf:1").consumed is False
        store.mark_consumed("conf:1")
        assert store.get("conf:1").consumed is True

    def test_count(self) -> None:
        store = ConfirmationStore()
        assert store.count() == 0
        store.add(ConfirmationRecord(
            confirmation_id="conf:1", candidate_id="c1", action_id="a",
            preview_id="p1", preview_fingerprint="f1", confirmed_at="t1",
            confirmation_token_secret="s1",
        ))
        assert store.count() == 1


# ---------------------------------------------------------------------------
# C. ConfirmationService.confirm
# ---------------------------------------------------------------------------
class TestConfirmationServiceConfirm:
    def test_confirm_available_candidate(self) -> None:
        """AVAILABLE candidate + READY preview should succeed."""
        service = ConfirmationService()
        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)
        record = service.confirm(candidate, preview)
        assert record.confirmation_id.startswith("conf:")
        assert record.candidate_id == candidate.candidate_id
        assert record.action_id == candidate.action_id
        assert record.preview_id == preview.preview_id
        assert record.preview_fingerprint == preview.fingerprint
        assert record.consumed is False

    def test_confirm_proposed_raises(self) -> None:
        """PROPOSED candidate cannot be confirmed."""
        service = ConfirmationService()
        candidate = _make_candidate(
            CandidateStatus.PROPOSED,
            action_id="disk.cleanup_logs",
            candidate_id="proposed.disk.cleanup_logs",
        )
        preview = _make_ready_preview(candidate)
        with pytest.raises(ProposedCandidateError):
            service.confirm(candidate, preview)

    def test_confirm_blocked_raises(self) -> None:
        """BLOCKED candidate cannot be confirmed."""
        service = ConfirmationService()
        candidate = _make_candidate(
            CandidateStatus.BLOCKED,
            action_id="startup.disable_entry",
            candidate_id="blocked.startup.disable_entry",
        )
        preview = _make_ready_preview(candidate)
        with pytest.raises(BlockedCandidateError):
            service.confirm(candidate, preview)

    def test_confirm_insufficient_evidence_raises(self) -> None:
        """INSUFFICIENT_EVIDENCE candidate cannot be confirmed."""
        service = ConfirmationService()
        candidate = _make_candidate(
            CandidateStatus.INSUFFICIENT_EVIDENCE,
            candidate_id="insufficient.disk.cleanup_temp",
        )
        preview = _make_ready_preview(candidate)
        with pytest.raises(InsufficientEvidenceError):
            service.confirm(candidate, preview)

    def test_confirm_stale_candidate_raises(self) -> None:
        """STALE candidate cannot be confirmed."""
        service = ConfirmationService()
        candidate = _make_candidate(
            CandidateStatus.STALE,
            candidate_id="stale.disk.cleanup_temp",
        )
        preview = _make_ready_preview(candidate)
        with pytest.raises(StalePreviewError):
            service.confirm(candidate, preview)

    def test_confirm_stale_preview_raises(self) -> None:
        """STALE preview cannot be confirmed even if candidate is AVAILABLE."""
        service = ConfirmationService()
        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        stale_preview = Preview(
            preview_id="preview:stale",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at="2026-01-01T00:00:00",
            status=PreviewStatus.STALE,
            title="Stale preview",
            summary="Evidence expired",
            target="Unknown",
            affected_count=0,
            affected_bytes=0,
        )
        with pytest.raises(StalePreviewError):
            service.confirm(candidate, stale_preview)

    def test_confirm_insufficient_evidence_preview_raises(self) -> None:
        """INSUFFICIENT_EVIDENCE preview cannot be confirmed."""
        service = ConfirmationService()
        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        insuff_preview = Preview(
            preview_id="preview:insuff",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at="2026-01-01T00:00:00",
            status=PreviewStatus.INSUFFICIENT_EVIDENCE,
            title="Insufficient",
            summary="Not enough evidence",
            target="Unknown",
            affected_count=0,
            affected_bytes=0,
        )
        with pytest.raises(InsufficientEvidenceError):
            service.confirm(candidate, insuff_preview)

    def test_confirm_blocked_preview_raises(self) -> None:
        """BLOCKED preview cannot be confirmed."""
        service = ConfirmationService()
        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        blocked_preview = Preview(
            preview_id="preview:blocked",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at="2026-01-01T00:00:00",
            status=PreviewStatus.BLOCKED,
            title="Blocked",
            summary="Blocked",
            target="Blocked",
            affected_count=0,
            affected_bytes=0,
        )
        with pytest.raises(BlockedCandidateError):
            service.confirm(candidate, blocked_preview)

    def test_confirm_unavailable_preview_raises(self) -> None:
        """UNAVAILABLE preview cannot be confirmed."""
        service = ConfirmationService()
        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        # Build a preview then override status to UNAVAILABLE
        preview = _make_ready_preview(candidate)
        # Create a new preview-like object with UNAVAILABLE status
        unavailable_preview = Preview(
            preview_id=preview.preview_id,
            candidate_id=preview.candidate_id,
            action_id=preview.action_id,
            generated_at=preview.generated_at,
            status=PreviewStatus.UNAVAILABLE,
            title=preview.title,
            summary=preview.summary,
            target=preview.target,
            affected_count=preview.affected_count,
            affected_bytes=preview.affected_bytes,
        )
        with pytest.raises(InvalidPreviewStatusError):
            service.confirm(candidate, unavailable_preview)

    def test_confirm_error_preview_raises(self) -> None:
        """ERROR preview cannot be confirmed."""
        service = ConfirmationService()
        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        error_preview = Preview(
            preview_id="preview:error",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at="2026-01-01T00:00:00",
            status=PreviewStatus.ERROR,
            title="Error",
            summary="Error",
            target="Error",
            affected_count=0,
            affected_bytes=0,
        )
        with pytest.raises(InvalidPreviewStatusError):
            service.confirm(candidate, error_preview)

    def test_confirm_preview_mismatch_candidate_id(self) -> None:
        """Preview with wrong candidate_id should fail."""
        service = ConfirmationService()
        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        mismatched_preview = Preview(
            preview_id="preview:wrong",
            candidate_id="wrong_candidate",
            action_id=candidate.action_id,
            generated_at="2026-01-01T00:00:00",
            status=PreviewStatus.READY,
            title="Wrong",
            summary="Wrong candidate",
            target="Wrong",
            affected_count=0,
            affected_bytes=0,
        )
        with pytest.raises(PreviewMismatchError):
            service.confirm(candidate, mismatched_preview)

    def test_confirm_preview_mismatch_action_id(self) -> None:
        """Preview with wrong action_id should fail."""
        service = ConfirmationService()
        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        mismatched_preview = Preview(
            preview_id="preview:wrong",
            candidate_id=candidate.candidate_id,
            action_id="wrong.action",
            generated_at="2026-01-01T00:00:00",
            status=PreviewStatus.READY,
            title="Wrong",
            summary="Wrong action",
            target="Wrong",
            affected_count=0,
            affected_bytes=0,
        )
        with pytest.raises(PreviewMismatchError):
            service.confirm(candidate, mismatched_preview)


# ---------------------------------------------------------------------------
# D. ConfirmationService.validate
# ---------------------------------------------------------------------------
class TestConfirmationServiceValidate:
    def test_validate_existing_record(self) -> None:
        service = ConfirmationService()
        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)
        record = service.confirm(candidate, preview)
        validated = service.validate(record.confirmation_id, candidate, preview)
        assert validated.confirmation_id == record.confirmation_id

    def test_validate_nonexistent_raises(self) -> None:
        service = ConfirmationService()
        candidate = _make_candidate()
        preview = _make_ready_preview(candidate)
        with pytest.raises(ConfirmationError, match="not found"):
            service.validate("nonexistent", candidate, preview)

    def test_validate_consumed_raises(self) -> None:
        service = ConfirmationService()
        candidate = _make_candidate()
        preview = _make_ready_preview(candidate)
        record = service.confirm(candidate, preview)
        service.consume(record.confirmation_id, candidate, preview)
        with pytest.raises(ConfirmationAlreadyUsedError):
            service.validate(record.confirmation_id, candidate, preview)

    def test_validate_wrong_candidate_raises(self) -> None:
        service = ConfirmationService()
        candidate = _make_candidate()
        preview = _make_ready_preview(candidate)
        record = service.confirm(candidate, preview)
        wrong_candidate = _make_candidate(
            candidate_id="wrong.candidate",
            action_id="disk.cleanup_temp",
        )
        with pytest.raises(PreviewMismatchError):
            service.validate(record.confirmation_id, wrong_candidate, preview)


# ---------------------------------------------------------------------------
# E. ConfirmationService.consume
# ---------------------------------------------------------------------------
class TestConfirmationServiceConsume:
    def test_consume_marks_as_consumed(self) -> None:
        service = ConfirmationService()
        candidate = _make_candidate()
        preview = _make_ready_preview(candidate)
        record = service.confirm(candidate, preview)
        consumed = service.consume(record.confirmation_id, candidate, preview)
        assert consumed.consumed is True

    def test_consume_then_validate_raises(self) -> None:
        service = ConfirmationService()
        candidate = _make_candidate()
        preview = _make_ready_preview(candidate)
        record = service.confirm(candidate, preview)
        service.consume(record.confirmation_id, candidate, preview)
        with pytest.raises(ConfirmationAlreadyUsedError):
            service.validate(record.confirmation_id, candidate, preview)


# ---------------------------------------------------------------------------
# F. ConfirmationService stores records
# ---------------------------------------------------------------------------
class TestConfirmationServiceStorage:
    def test_records_stored_in_store(self) -> None:
        store = ConfirmationStore()
        service = ConfirmationService(store=store)
        candidate = _make_candidate()
        preview = _make_ready_preview(candidate)
        record = service.confirm(candidate, preview)
        assert store.count() == 1
        assert store.get(record.confirmation_id) is not None

    def test_multiple_confirmations(self) -> None:
        store = ConfirmationStore()
        service = ConfirmationService(store=store)
        candidate1 = _make_candidate(
            candidate_id="c1",
            action_id="disk.cleanup_temp",
        )
        candidate2 = _make_candidate(
            candidate_id="c2",
            action_id="user_temp_quarantine",
        )
        preview1 = _make_ready_preview(candidate1)
        preview2 = _make_ready_preview(candidate2)
        r1 = service.confirm(candidate1, preview1)
        r2 = service.confirm(candidate2, preview2)
        assert store.count() == 2
        assert r1.confirmation_id != r2.confirmation_id


# ---------------------------------------------------------------------------
# G. Module-level convenience
# ---------------------------------------------------------------------------
class TestModuleLevelConvenience:
    def test_confirm_candidate_function(self) -> None:
        candidate = _make_candidate()
        preview = _make_ready_preview(candidate)
        record = confirm_candidate(candidate, preview)
        assert record.confirmation_id.startswith("conf:")

    def test_get_confirmation_service_returns_same_instance(self) -> None:
        s1 = get_confirmation_service()
        s2 = get_confirmation_service()
        assert s1 is s2


# ---------------------------------------------------------------------------
# H. No execution authority
# ---------------------------------------------------------------------------
class TestNoExecutionAuthority:
    def test_no_executor_import(self) -> None:
        """confirmation_service.py must not import executor."""
        path = os.path.join("app", "remediation", "confirmation_service.py")
        with open(path) as f:
            content = f.read()
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "executor" not in node.module.lower()

    def test_no_subprocess_import(self) -> None:
        path = os.path.join("app", "remediation", "confirmation_service.py")
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

    def test_no_shell_true(self) -> None:
        path = os.path.join("app", "remediation", "confirmation_service.py")
        with open(path) as f:
            content = f.read()
        assert "shell=True" not in content
        assert "shell = True" not in content

    def test_no_filesystem_write(self) -> None:
        """confirmation_service.py must not write files."""
        path = os.path.join("app", "remediation", "confirmation_service.py")
        with open(path) as f:
            content = f.read()
        assert "open(" not in content or "open(path) as f" in content
        assert "write(" not in content

    def test_confirmation_does_not_execute(self) -> None:
        """Confirming a candidate does NOT execute the action."""
        candidate = _make_candidate()
        preview = _make_ready_preview(candidate)
        record = confirm_candidate(candidate, preview)
        # Record exists, but action was not executed
        assert record.consumed is False


# ---------------------------------------------------------------------------
# I. Single-use enforcement
# ---------------------------------------------------------------------------
class TestSingleUseEnforcement:
    def test_token_is_single_use(self) -> None:
        """A confirmation token can only be consumed once."""
        service = ConfirmationService()
        candidate = _make_candidate()
        preview = _make_ready_preview(candidate)
        record = service.confirm(candidate, preview)

        # First consume succeeds
        consumed = service.consume(record.confirmation_id, candidate, preview)
        assert consumed.consumed is True

        # Second consume fails
        with pytest.raises(ConfirmationAlreadyUsedError):
            service.consume(record.confirmation_id, candidate, preview)


# ---------------------------------------------------------------------------
# J. No --yes/--force bypass
# ---------------------------------------------------------------------------
class TestNoForceBypass:
    def test_cli_has_no_force_flag(self) -> None:
        """The confirm-candidate CLI command has no --yes or --force flag."""
        import subprocess
        result = subprocess.run(
            ["python", "-m", "app.cli", "actions", "confirm-candidate", "--help"],
            capture_output=True,
            text=True,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        output = result.stdout + result.stderr
        assert "--yes" not in output.lower()
        assert "--force" not in output.lower()
        assert "-y" not in output.split()


# ---------------------------------------------------------------------------
# K. Implementation_status vs preview_status independence
# ---------------------------------------------------------------------------
class TestStatusDimensionsIndependent:
    """Phase 11B.1 regression: implementation_status and preview_status are independent."""

    def test_confirmation_uses_preview_status_not_implementation(self) -> None:
        """Confirmation validates against PreviewStatus, not implementation_status."""
        service = ConfirmationService()
        candidate = _make_candidate(CandidateStatus.AVAILABLE)
        preview = _make_ready_preview(candidate)
        # implementation_status is "implemented" but that's not what gates confirmation
        assert preview.implementation_status == "implemented"
        assert preview.status == PreviewStatus.READY
        # Confirmation should succeed because preview.status is READY
        record = service.confirm(candidate, preview)
        assert record.confirmation_id.startswith("conf:")


# ---------------------------------------------------------------------------
# L. Proposed/blocked actions can never reach confirmation
# ---------------------------------------------------------------------------
class TestProposedBlockedNeverConfirm:
    PROPOSED_STATUSES = {CandidateStatus.PROPOSED}
    BLOCKED_STATUSES = {CandidateStatus.BLOCKED}

    @pytest.mark.parametrize("status", list(PROPOSED_STATUSES))
    def test_proposed_rejected(self, status: CandidateStatus) -> None:
        service = ConfirmationService()
        candidate = _make_candidate(status)
        preview = _make_ready_preview(candidate)
        with pytest.raises(ConfirmationError):
            service.confirm(candidate, preview)

    @pytest.mark.parametrize("status", list(BLOCKED_STATUSES))
    def test_blocked_rejected(self, status: CandidateStatus) -> None:
        service = ConfirmationService()
        candidate = _make_candidate(status)
        preview = _make_ready_preview(candidate)
        with pytest.raises(ConfirmationError):
            service.confirm(candidate, preview)


# ---------------------------------------------------------------------------
# M. Confirmation record is immutable
# ---------------------------------------------------------------------------
class TestConfirmationRecordImmutability:
    def test_record_frozen(self) -> None:
        record = ConfirmationRecord(
            confirmation_id="conf:1",
            candidate_id="c1",
            action_id="disk.cleanup_temp",
            preview_id="preview:c1",
            preview_fingerprint="abc123",
            confirmed_at="2026-01-01T00:00:00",
            confirmation_token_secret="secret123",
        )
        with pytest.raises(AttributeError):
            record.confirmation_id = "hacked"  # type: ignore[misc]
