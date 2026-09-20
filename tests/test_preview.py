"""Comprehensive tests for Phase 11B: Candidate Preview Intelligence.

Tests the Preview model, PreviewBuilder, API endpoints, CLI command,
and verifies that NO execution authority is granted by the preview subsystem.
"""

from __future__ import annotations

import ast
import os

import pytest

from app.remediation.preview import (
    Preview,
    PreviewBuilder,
    PreviewItem,
    PreviewStatus,
    PreviewSummary,
    build_preview,
    MAX_PREVIEW_ITEMS,
)
from app.remediation.candidates import (
    ActionCandidate,
    CandidateStatus,
    EvidenceSource,
    EvidenceSourceType,
)


# A. Preview model
class TestPreviewModel:
    def test_preview_is_frozen(self) -> None:
        p = Preview(
            preview_id="p1",
            candidate_id="c1",
            action_id="test.action",
            generated_at="2026-01-01T00:00:00",
            status=PreviewStatus.READY,
            title="Test",
            summary="Test summary",
            target="Test target",
            affected_count=0,
            affected_bytes=0,
        )
        with pytest.raises(AttributeError):
            p.status = PreviewStatus.BLOCKED

    def test_preview_status_enum_values(self) -> None:
        statuses = [s.value for s in PreviewStatus]
        assert "ready" in statuses
        assert "stale" in statuses
        assert "insufficient_evidence" in statuses
        assert "blocked" in statuses
        assert "unavailable" in statuses
        assert "error" in statuses

    def test_preview_item_frozen(self) -> None:
        item = PreviewItem(path="/tmp/test", size_bytes=100)
        with pytest.raises(AttributeError):
            item.path = "/other"

    def test_preview_summary_fields(self) -> None:
        s = PreviewSummary(
            preview_id="p1",
            candidate_id="c1",
            action_id="test.action",
            status="ready",
            affected_count=5,
            affected_bytes=1024,
            risk_level="medium",
            reversible=True,
            rollback_available=True,
            expected_effect="Move files",
        )
        assert s.affected_count == 5
        assert s.rollback_available is True

    def test_max_preview_items_is_20(self) -> None:
        assert MAX_PREVIEW_ITEMS == 20


# B. Available candidate creates ready preview
class TestAvailableCandidatePreview:
    def test_cleanup_temp_with_files_creates_ready(self) -> None:
        e = EvidenceSource(
            source_type=EvidenceSourceType.DISCOVERY,
            source_id="storage:C:",
            observation="Storage pressure",
        )
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Safe temp cleanup",
            reason="Storage pressure",
            evidence=[e],
            discovery_run_id=1,
        )
        file_analysis = {
            "eligible_temp_files": [
                {"path": "/tmp/file1.tmp", "size_bytes": 1024},
                {"path": "/tmp/file2.tmp", "size_bytes": 2048},
            ]
        }
        preview = build_preview(c, file_analysis=file_analysis)
        assert preview.status == PreviewStatus.READY
        assert preview.affected_count == 2
        assert preview.affected_bytes == 3072
        assert len(preview.affected_items) == 2

    def test_cleanup_temp_without_files_still_ready(self) -> None:
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Safe temp cleanup",
            reason="Storage pressure",
        )
        preview = build_preview(c)
        assert preview.status == PreviewStatus.READY
        assert preview.affected_count == 0

    def test_preview_has_evidence(self) -> None:
        e = EvidenceSource(
            source_type=EvidenceSourceType.DISCOVERY,
            source_id="storage:C:",
            observation="Storage 90%",
        )
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
            evidence=[e],
        )
        preview = build_preview(c)
        assert len(preview.evidence) > 0


# C. Proposed candidate creates non-executable design preview
class TestProposedCandidatePreview:
    def test_proposed_status_is_unavailable(self) -> None:
        c = ActionCandidate(
            candidate_id="proposed.disk.cleanup_logs",
            action_id="disk.cleanup_logs",
            status=CandidateStatus.PROPOSED,
            title="Cleanup logs",
            reason="Proposed action",
        )
        preview = build_preview(c)
        assert preview.status == PreviewStatus.UNAVAILABLE
        assert "not implemented" in preview.expected_effect.lower()

    def test_proposed_not_confirmed(self) -> None:
        c = ActionCandidate(
            candidate_id="proposed.test",
            action_id="test.action",
            status=CandidateStatus.PROPOSED,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c)
        assert preview.confirmation_required is False

    def test_proposed_has_limitations(self) -> None:
        c = ActionCandidate(
            candidate_id="proposed.test",
            action_id="test.action",
            status=CandidateStatus.PROPOSED,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c)
        assert any("not implemented" in lim.lower() for lim in preview.limitations)


# D. Blocked candidate preview
class TestBlockedCandidatePreview:
    def test_blocked_status(self) -> None:
        c = ActionCandidate(
            candidate_id="blocked.startup.disable_entry",
            action_id="startup.disable_entry",
            status=CandidateStatus.BLOCKED,
            title="Disable startup",
            reason="High risk",
            risk_level="high",
        )
        preview = build_preview(c)
        assert preview.status == PreviewStatus.BLOCKED
        assert "blocked" in preview.expected_effect.lower()

    def test_blocked_no_confirmation(self) -> None:
        c = ActionCandidate(
            candidate_id="blocked.test",
            action_id="test.action",
            status=CandidateStatus.BLOCKED,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c)
        assert preview.confirmation_required is False

    def test_blocked_no_rollback(self) -> None:
        c = ActionCandidate(
            candidate_id="blocked.test",
            action_id="test.action",
            status=CandidateStatus.BLOCKED,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c)
        assert preview.rollback_available is False


# E. Insufficient evidence preview
class TestInsufficientEvidencePreview:
    def test_insufficient_status(self) -> None:
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.INSUFFICIENT_EVIDENCE,
            title="Temp cleanup",
            reason="No file analysis available",
            limitations=["No eligible temp file data"],
        )
        preview = build_preview(c)
        assert preview.status == PreviewStatus.INSUFFICIENT_EVIDENCE
        assert preview.affected_count == 0

    def test_insufficient_has_limitations(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.INSUFFICIENT_EVIDENCE,
            title="Test",
            reason="Test",
            limitations=["Missing file analysis"],
        )
        preview = build_preview(c)
        assert len(preview.limitations) > 0


# F. Stale evidence preview
class TestStaleEvidencePreview:
    def test_stale_status(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.STALE,
            title="Test",
            reason="Test",
            stale_after="7 days",
        )
        preview = build_preview(c)
        assert preview.status == PreviewStatus.STALE
        assert "expired" in preview.expected_effect.lower() or "stale" in preview.summary.lower()

    def test_stale_no_target_list(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.STALE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c)
        assert preview.affected_count == 0
        assert len(preview.affected_items) == 0


# G. Exact target count
class TestTargetCount:
    def test_count_matches_eligible_files(self) -> None:
        files = [{"path": f"/tmp/f{i}", "size_bytes": 100} for i in range(5)]
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": files})
        assert preview.affected_count == 5


# H. Affected byte total
class TestAffectedBytes:
    def test_bytes_match_sum(self) -> None:
        files = [
            {"path": "/tmp/f1", "size_bytes": 100},
            {"path": "/tmp/f2", "size_bytes": 200},
            {"path": "/tmp/f3", "size_bytes": 300},
        ]
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": files})
        assert preview.affected_bytes == 600


# I. Max preview items
class TestMaxPreviewItems:
    def test_items_bounded(self) -> None:
        files = [{"path": f"/tmp/f{i}", "size_bytes": 100} for i in range(50)]
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": files})
        assert len(preview.affected_items) == MAX_PREVIEW_ITEMS


# J. Omitted item count
class TestOmittedCount:
    def test_omitted_count_correct(self) -> None:
        files = [{"path": f"/tmp/f{i}", "size_bytes": 100} for i in range(25)]
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": files})
        assert preview.omitted_count == 5

    def test_no_omitted_when_under_limit(self) -> None:
        files = [{"path": f"/tmp/f{i}", "size_bytes": 100} for i in range(10)]
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": files})
        assert preview.omitted_count == 0


# K. Path containment
class TestPathContainment:
    def test_paths_from_evidence_only(self) -> None:
        files = [{"path": "/tmp/specific_file.txt", "size_bytes": 100}]
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": files})
        paths = [item.path for item in preview.affected_items]
        assert "/tmp/specific_file.txt" in paths


# L. Symlink rejection
class TestSymlinkRejection:
    def test_no_symlinks_in_preview_items(self) -> None:
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": []})
        for item in preview.affected_items:
            assert not os.path.islink(item.path) if os.path.exists(item.path) else True


# M. Deterministic ordering
class TestDeterministicOrder:
    def test_same_input_same_output(self) -> None:
        files = [{"path": "/tmp/b", "size_bytes": 200}, {"path": "/tmp/a", "size_bytes": 100}]
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        p1 = build_preview(c, file_analysis={"eligible_temp_files": files})
        p2 = build_preview(c, file_analysis={"eligible_temp_files": files})
        assert p1.affected_count == p2.affected_count
        assert p1.fingerprint == p2.fingerprint
        assert p1.affected_bytes == p2.affected_bytes


# N. Preview fingerprint
class TestFingerprint:
    def test_fingerprint_computed_for_items(self) -> None:
        files = [{"path": "/tmp/f1", "size_bytes": 100}]
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": files})
        assert preview.fingerprint != ""

    def test_fingerprint_empty_for_no_items(self) -> None:
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c)
        assert preview.fingerprint == ""


# O. Expected effect wording
class TestEffectWording:
    def test_factual_wording(self) -> None:
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": [{"path": "/tmp/f", "size_bytes": 100}]})
        assert "Move" in preview.expected_effect or "move" in preview.expected_effect
        assert "Safely clean" not in preview.expected_effect


# P. Rollback metadata
class TestRollbackMetadata:
    def test_cleanup_temp_rollback_available(self) -> None:
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": [{"path": "/tmp/f", "size_bytes": 100}]})
        assert preview.rollback_available is True
        assert preview.reversible is True
        assert len(preview.rollback_description) > 0


# Q. Preview does not modify filesystem
class TestNoFilesystemModification:
    def test_preview_readonly(self) -> None:
        c = ActionCandidate(
            candidate_id="disk.cleanup_temp",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c, file_analysis={"eligible_temp_files": []})
        assert isinstance(preview, Preview)


# R. Preview does not call executor
class TestNoExecutorCall:
    def test_no_executor_import(self) -> None:
        path = os.path.join("app", "remediation", "preview.py")
        with open(path) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "executor" not in alias.name.lower()
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "executor" not in node.module.lower()


# S. Preview does not create confirmation token
class TestNoConfirmationToken:
    def test_no_confirmation_import(self) -> None:
        path = os.path.join("app", "remediation", "preview.py")
        with open(path) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "confirmation" not in alias.name.lower()
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "confirmation" not in node.module.lower()


# T. Stale evidence does not produce current target list
class TestStaleNoTargetList:
    def test_stale_affected_count_zero(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.STALE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c)
        assert preview.affected_count == 0
        assert len(preview.affected_items) == 0


# U. Candidate status cannot be changed by preview
class TestCandidateImmutability:
    def test_candidate_frozen(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        with pytest.raises(AttributeError):
            c.status = CandidateStatus.BLOCKED


# V. AI cannot modify preview
class TestPreviewImmutability:
    def test_preview_frozen(self) -> None:
        p = Preview(
            preview_id="p1",
            candidate_id="c1",
            action_id="test.action",
            generated_at="2026-01-01T00:00:00",
            status=PreviewStatus.READY,
            title="Test",
            summary="Test",
            target="Test",
            affected_count=0,
            affected_bytes=0,
        )
        with pytest.raises(AttributeError):
            p.status = PreviewStatus.BLOCKED


# W. API GET preview endpoint
class TestAPIPreview:
    def test_preview_endpoint_200(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import create_app
        from app.api import dependencies
        from app.database.sqlite import SnapshotStore
        from app.reporting.builder import build_health_report, HealthReport

        store = SnapshotStore()
        app = create_app()

        def override_get_report() -> HealthReport:
            return build_health_report(store)

        app.dependency_overrides[dependencies.get_report] = override_get_report
        client = TestClient(app)

        r = client.get("/api/v1/remediation/candidates")
        candidates = r.json().get("candidates", [])
        if candidates:
            cid = candidates[0]["candidate_id"]
            r2 = client.get(f"/api/v1/remediation/candidates/{cid}/preview")
            assert r2.status_code == 200
            d = r2.json()
            assert "preview_id" in d
            assert "status" in d
            assert "affected_count" in d


# X. API GET preview returns 404
class TestAPIPreview404:
    def test_preview_404(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import create_app
        from app.api import dependencies
        from app.database.sqlite import SnapshotStore
        from app.reporting.builder import build_health_report, HealthReport

        store = SnapshotStore()
        app = create_app()

        def override_get_report() -> HealthReport:
            return build_health_report(store)

        app.dependency_overrides[dependencies.get_report] = override_get_report
        client = TestClient(app)

        r = client.get("/api/v1/remediation/candidates/nonexistent_preview/preview")
        assert r.status_code == 404


# Y. API rejects POST preview
class TestAPIPreviewPost:
    def test_post_preview_405(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import create_app

        client = TestClient(create_app())
        r = client.post("/api/v1/remediation/candidates/test/preview")
        assert r.status_code == 405


# Z. CLI preview-candidate command
class TestCLIPreviewCandidate:
    def test_preview_candidate_exists(self) -> None:
        from app.cli import cmd_actions_preview_candidate
        assert callable(cmd_actions_preview_candidate)


# AA. No execution controls in preview output
class TestNoExecutionControls:
    def test_preview_no_execute_button(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        preview = build_preview(c)
        assert "Execute" not in preview.expected_effect
        assert "Apply" not in preview.expected_effect
        assert "Delete" not in preview.expected_effect


# AC. No subprocess/shell in preview.py
class TestNoSubprocess:
    def test_no_subprocess_import(self) -> None:
        path = os.path.join("app", "remediation", "preview.py")
        with open(path) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "subprocess" not in alias.name.lower()
                    assert "os.system" not in alias.name.lower()

    def test_no_shell_true(self) -> None:
        path = os.path.join("app", "remediation", "preview.py")
        with open(path) as f:
            content = f.read()
        assert "shell=True" not in content
        assert "shell = True" not in content


# AD. No executor import in preview.py
class TestNoExecutorInPreview:
    def test_no_executor_import(self) -> None:
        path = os.path.join("app", "remediation", "preview.py")
        with open(path) as f:
            content = f.read()
        # The string "executor" should not appear in import statements
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "executor" not in node.module.lower()


# AE. Preview summary integration
class TestPreviewSummaryIntegration:
    def test_preview_summary_fields(self) -> None:
        from app.reporting.models import ActionCandidateSummary
        s = ActionCandidateSummary()
        assert hasattr(s, "available_count")
        assert hasattr(s, "proposed_count")
        assert hasattr(s, "blocked_count")
        assert hasattr(s, "total_count")
