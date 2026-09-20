"""Comprehensive tests for Phase 11A: Diagnostic-to-Action Intelligence.

Tests the action candidate models, policy engine, and integration.
Verifies that NO execution authority is granted by the candidate subsystem.
"""

from __future__ import annotations

import ast
import os

import pytest

from app.remediation.candidates import (
    ActionCandidate,
    CandidateStatus,
    CandidatesSummary,
    EvidenceSource,
    EvidenceSourceType,
)
from app.remediation.policy import (
    PolicyContext,
    evaluate_candidates,
    MAX_ACTION_CANDIDATES,
    MAX_EVIDENCE_ITEMS,
)


# A. ActionCandidate model
class TestActionCandidateModel:
    def test_candidate_is_frozen(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test reason",
        )
        with pytest.raises(AttributeError):
            c.status = CandidateStatus.BLOCKED

    def test_executable_always_false(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test reason",
        )
        assert c.executable is False

    def test_executable_false_even_when_available(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test reason",
        )
        assert c.status == CandidateStatus.AVAILABLE
        assert c.executable is False

    def test_candidate_fields(self) -> None:
        e = EvidenceSource(
            source_type=EvidenceSourceType.DISCOVERY,
            source_id="test:1",
            observation="test observation",
        )
        c = ActionCandidate(
            candidate_id="c1",
            action_id="disk.cleanup_temp",
            status=CandidateStatus.AVAILABLE,
            title="Safe temp cleanup",
            reason="Storage pressure",
            evidence=[e],
            source_finding_ids=[1, 2],
            source_diagnostic_ids=["perf:cpu"],
            discovery_run_id=5,
            confidence_basis="deterministic_policy",
            eligibility_status="eligible",
            implementation_status="implemented",
            risk_level="medium",
            blast_radius="user_directory",
            reversible=True,
            requires_admin=False,
            preview_available=True,
            rollback_available=True,
            limitations=["test limitation"],
            stale_after="7 days",
        )
        assert c.candidate_id == "c1"
        assert c.discovery_run_id == 5
        assert len(c.evidence) == 1
        assert len(c.source_finding_ids) == 2


# B. Evidence binding
class TestEvidenceBinding:
    def test_evidence_source_model(self) -> None:
        e = EvidenceSource(
            source_type=EvidenceSourceType.DISCOVERY,
            source_id="storage:C:",
            observation="C: is 90% full",
            value=90.0,
            interpretation="critical",
        )
        assert e.source_type == EvidenceSourceType.DISCOVERY
        assert e.value == 90.0

    def test_evidence_is_frozen(self) -> None:
        e = EvidenceSource(
            source_type=EvidenceSourceType.DIAGNOSTIC,
            source_id="test",
            observation="test",
        )
        with pytest.raises(AttributeError):
            e.observation = "changed"

    def test_candidate_has_evidence_list(self) -> None:
        e = EvidenceSource(
            source_type=EvidenceSourceType.FINDING,
            source_id="finding:1",
            observation="Critical disk finding",
        )
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
            evidence=[e],
        )
        assert len(c.evidence) == 1
        assert c.evidence[0].source_type == EvidenceSourceType.FINDING

    def test_multiple_evidence_sources(self) -> None:
        e1 = EvidenceSource(source_type=EvidenceSourceType.DISCOVERY, source_id="s1", observation="o1")
        e2 = EvidenceSource(source_type=EvidenceSourceType.DIAGNOSTIC, source_id="s2", observation="o2")
        e3 = EvidenceSource(source_type=EvidenceSourceType.FINDING, source_id="s3", observation="o3")
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
            evidence=[e1, e2, e3],
        )
        assert len(c.evidence) == 3

    def test_evidence_source_types(self) -> None:
        for st in EvidenceSourceType:
            e = EvidenceSource(source_type=st, source_id="x", observation="x")
            assert e.source_type == st


# C. Available candidate for valid disk.cleanup_temp evidence
class TestCleanupTempCandidate:
    def test_available_with_storage_pressure_and_files(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 90.7}]},
            file_analysis={"eligible_temp_files": [{"path": "/tmp/f1", "size_bytes": 1024}]},
        )
        result = evaluate_candidates(ctx)
        available = [c for c in result.candidates if c.action_id == "disk.cleanup_temp"]
        assert len(available) == 1
        assert available[0].status == CandidateStatus.AVAILABLE
        assert available[0].executable is False
        assert "Storage pressure" in available[0].reason

    def test_available_candidate_has_evidence(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 91.0}]},
            file_analysis={"eligible_temp_files": [{"path": "/tmp/f1", "size_bytes": 500}]},
        )
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "disk.cleanup_temp"][0]
        assert len(c.evidence) > 0
        assert any(e.source_type == EvidenceSourceType.DISCOVERY for e in c.evidence)

    def test_available_candidate_metadata(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 92.0}]},
            file_analysis={"eligible_temp_files": [{"path": "/tmp/f", "size_bytes": 100}]},
        )
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "disk.cleanup_temp"][0]
        assert c.implementation_status == "implemented"
        assert c.eligibility_status == "eligible"
        assert c.risk_level == "medium"
        assert c.reversible is True
        assert c.preview_available is True
        assert c.rollback_available is True


# D. No candidate without evidence
class TestNoEvidenceNoCandidate:
    def test_no_available_without_storage_pressure(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 50.0}]},
        )
        result = evaluate_candidates(ctx)
        available = [
            c for c in result.candidates
            if c.action_id == "disk.cleanup_temp" and c.status == CandidateStatus.AVAILABLE
        ]
        assert len(available) == 0

    def test_no_candidate_without_context(self) -> None:
        ctx = PolicyContext()
        result = evaluate_candidates(ctx)
        available = [c for c in result.candidates if c.status == CandidateStatus.AVAILABLE]
        assert len(available) == 0

    def test_no_user_temp_quarantine_without_files(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        quarantine = [c for c in result.candidates if c.action_id == "user_temp_quarantine"]
        assert len(quarantine) == 0


# E. Insufficient evidence state
class TestInsufficientEvidence:
    def test_insufficient_when_storage_high_but_no_files(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 85.0}]},
            file_analysis=None,
        )
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "disk.cleanup_temp"]
        assert len(c) == 1
        assert c[0].status == CandidateStatus.INSUFFICIENT_EVIDENCE
        assert any("file analysis" in lim.lower() for lim in c[0].limitations)


# F. Stale evidence state
class TestStaleEvidence:
    def test_stale_after_field_present(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 90.0}]},
            file_analysis={"eligible_temp_files": [{"path": "/tmp/f", "size_bytes": 100}]},
        )
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "disk.cleanup_temp"]
        assert len(c) == 1
        assert c[0].stale_after != ""

    def test_generated_at_populated(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 90.0}]},
            file_analysis={"eligible_temp_files": [{"path": "/tmp/f", "size_bytes": 100}]},
        )
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "disk.cleanup_temp"]
        assert c[0].generated_at != ""


# G. Implemented action eligible
class TestImplementedAction:
    def test_available_status_for_implemented(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 90.0}]},
            file_analysis={"eligible_temp_files": [{"path": "/tmp/f", "size_bytes": 100}]},
        )
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "disk.cleanup_temp"]
        assert len(c) == 1
        assert c[0].implementation_status == "implemented"
        assert c[0].eligibility_status == "eligible"


# H. Proposed action remains proposed
class TestProposedAction:
    def test_proposed_actions_remain_proposed(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        proposed = [c for c in result.candidates if c.status == CandidateStatus.PROPOSED]
        assert len(proposed) > 0
        for c in proposed:
            assert c.implementation_status == "proposed"
            assert c.executable is False

    def test_proposed_disk_cleanup_logs(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "disk.cleanup_logs"]
        assert len(c) == 1
        assert c[0].status == CandidateStatus.PROPOSED

    def test_proposed_browser_cache_clear(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "browser.cache_clear"]
        assert len(c) == 1
        assert c[0].status == CandidateStatus.PROPOSED

    def test_proposed_update_check_only(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "update.check_only"]
        assert len(c) == 1
        assert c[0].status == CandidateStatus.PROPOSED


# I. Blocked action remains blocked
class TestBlockedAction:
    def test_blocked_actions_remain_blocked(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        blocked = [c for c in result.candidates if c.status == CandidateStatus.BLOCKED]
        assert len(blocked) > 0
        for c in blocked:
            assert c.implementation_status == "blocked"
            assert c.executable is False

    def test_blocked_startup_disable(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "startup.disable_entry"]
        assert len(c) == 1
        assert c[0].status == CandidateStatus.BLOCKED
        assert "blocked" in c[0].reason.lower()

    def test_blocked_service_actions(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        service_blocked = [c for c in result.candidates if c.action_id.startswith("service.")]
        assert len(service_blocked) == 2
        for c in service_blocked:
            assert c.status == CandidateStatus.BLOCKED

    def test_blocked_software_uninstall(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "software.uninstall"]
        assert len(c) == 1
        assert c[0].status == CandidateStatus.BLOCKED


# J. Unknown action rejected
class TestUnknownAction:
    def test_unknown_action_not_in_candidates(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        unknown = [c for c in result.candidates if c.action_id == "unknown.action"]
        assert len(unknown) == 0

    def test_nonexistent_action_not_generated(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        ids = [c.action_id for c in result.candidates]
        assert "fake.action.id" not in ids


# K. Dependency failure handled
class TestDependencyHandling:
    def test_no_dependencies_for_current_actions(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        for c in result.candidates:
            assert isinstance(c.limitations, list)


# L. Freshness validation
class TestFreshnessValidation:
    def test_stale_after_populated_for_cleanup(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 90.0}]},
            file_analysis={"eligible_temp_files": [{"path": "/tmp/f", "size_bytes": 100}]},
        )
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "disk.cleanup_temp"][0]
        assert "7 days" in c.stale_after


# M. Source finding/run validation
class TestSourceValidation:
    def test_discovery_run_id_propagated(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=42,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 90.0}]},
            file_analysis={"eligible_temp_files": [{"path": "/tmp/f", "size_bytes": 100}]},
        )
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "disk.cleanup_temp"][0]
        assert c.discovery_run_id == 42

    def test_discovery_run_id_none_when_not_set(self) -> None:
        ctx = PolicyContext()
        result = evaluate_candidates(ctx)
        for c in result.candidates:
            if c.status in (CandidateStatus.AVAILABLE, CandidateStatus.INSUFFICIENT_EVIDENCE):
                assert c.discovery_run_id is None


# N. Candidate limits
class TestCandidateLimits:
    def test_total_does_not_exceed_limit(self) -> None:
        ctx = PolicyContext(discovery_run_id=1)
        result = evaluate_candidates(ctx)
        assert result.total_count <= MAX_ACTION_CANDIDATES

    def test_max_action_candidates_is_20(self) -> None:
        assert MAX_ACTION_CANDIDATES == 20


# O. Bounded evidence
class TestBoundedEvidence:
    def test_max_evidence_items_is_10(self) -> None:
        assert MAX_EVIDENCE_ITEMS == 10

    def test_evidence_bounded_in_candidate(self) -> None:
        files = [{"path": f"/tmp/f{i}", "size_bytes": 100} for i in range(20)]
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 90.0}]},
            file_analysis={"eligible_temp_files": files},
        )
        result = evaluate_candidates(ctx)
        c = [x for x in result.candidates if x.action_id == "disk.cleanup_temp"][0]
        assert len(c.evidence) <= MAX_EVIDENCE_ITEMS


# P. Deterministic policy output
class TestDeterministic:
    def test_same_inputs_same_outputs(self) -> None:
        ctx = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 90.0}]},
            file_analysis={"eligible_temp_files": [{"path": "/tmp/f", "size_bytes": 100}]},
        )
        r1 = evaluate_candidates(ctx)
        r2 = evaluate_candidates(ctx)
        assert r1.total_count == r2.total_count
        assert r1.available_count == r2.available_count
        ids1 = [c.candidate_id for c in r1.candidates]
        ids2 = [c.candidate_id for c in r2.candidates]
        assert ids1 == ids2

    def test_different_inputs_different_outputs(self) -> None:
        ctx1 = PolicyContext(discovery_run_id=1)
        ctx2 = PolicyContext(
            discovery_run_id=1,
            storage_summary={"partitions": [{"device": "C:", "usage_percent": 90.0}]},
            file_analysis={"eligible_temp_files": [{"path": "/tmp/f", "size_bytes": 100}]},
        )
        r1 = evaluate_candidates(ctx1)
        r2 = evaluate_candidates(ctx2)
        assert r1.available_count != r2.available_count


# Q. AI context includes candidates
class TestAIContextIntegration:
    def test_ai_context_has_candidates(self) -> None:
        from app.reporting.builder import build_health_report
        from app.ai.context import build_ai_context

        report = build_health_report()
        ctx = build_ai_context(report)
        assert hasattr(ctx, "action_candidates_summary")
        assert isinstance(ctx.action_candidates_summary, dict)

    def test_candidates_summary_structure(self) -> None:
        from app.reporting.builder import build_health_report
        from app.ai.context import build_ai_context

        report = build_health_report()
        ctx = build_ai_context(report)
        ac = ctx.action_candidates_summary
        if ac.get("available"):
            assert "available_count" in ac
            assert "proposed_count" in ac
            assert "blocked_count" in ac
            assert "candidates" in ac


# R. AI cannot change candidate status
class TestCandidateImmutability:
    def test_cannot_change_status(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        with pytest.raises(AttributeError):
            c.status = CandidateStatus.BLOCKED

    def test_cannot_change_executable(self) -> None:
        c = ActionCandidate(
            candidate_id="test",
            action_id="test.action",
            status=CandidateStatus.AVAILABLE,
            title="Test",
            reason="Test",
        )
        with pytest.raises(AttributeError):
            c.executable = True


# S. executable=false remains enforced
class TestExecutableAlwaysFalse:
    def test_property_returns_false(self) -> None:
        for status in CandidateStatus:
            c = ActionCandidate(
                candidate_id="test",
                action_id="test.action",
                status=status,
                title="Test",
                reason="Test",
            )
            assert c.executable is False, f"executable should be False for status={status}"


# T. API candidate endpoint
class TestAPICandidateEndpoint:
    def test_candidates_endpoint_returns_200(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app

        client = TestClient(app)
        r = client.get("/api/v1/remediation/candidates")
        assert r.status_code == 200

    def test_candidates_response_structure(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app

        client = TestClient(app)
        r = client.get("/api/v1/remediation/candidates")
        data = r.json()
        assert "candidates" in data
        assert "available_count" in data
        assert "total_count" in data

    def test_candidates_post_rejected(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app

        client = TestClient(app)
        r = client.post("/api/v1/remediation/candidates")
        assert r.status_code == 405


# U. Candidate detail endpoint
class TestAPICandidateDetail:
    def test_detail_nonexistent_returns_404(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app

        client = TestClient(app)
        r = client.get("/api/v1/remediation/candidates/nonexistent_candidate")
        assert r.status_code == 404

    def test_detail_post_rejected(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app

        client = TestClient(app)
        r = client.post("/api/v1/remediation/candidates/some_id")
        assert r.status_code == 405


# V. CLI candidates function exists
class TestCLICandidates:
    def test_cmd_actions_candidates_exists(self) -> None:
        from app.cli import cmd_actions_candidates
        assert callable(cmd_actions_candidates)

    def test_cli_imports(self) -> None:
        import importlib
        mod = importlib.import_module("app.cli")
        assert hasattr(mod, "cmd_actions_candidates")


# W. Dashboard rendering
class TestDashboardIntegration:
    def test_report_has_action_candidates(self) -> None:
        from app.reporting.builder import build_health_report
        from app.reporting.models import ActionCandidateSummary

        report = build_health_report()
        assert hasattr(report, "action_candidates")
        assert isinstance(report.action_candidates, ActionCandidateSummary)

    def test_candidates_summary_fields(self) -> None:
        from app.reporting.builder import build_health_report

        report = build_health_report()
        ac = report.action_candidates
        assert hasattr(ac, "available_count")
        assert hasattr(ac, "proposed_count")
        assert hasattr(ac, "blocked_count")
        assert hasattr(ac, "insufficient_evidence_count")
        assert hasattr(ac, "stale_count")
        assert hasattr(ac, "total_count")
        assert hasattr(ac, "candidates")


# X. No executor import
class TestNoExecutorImport:
    def test_policy_does_not_import_executor(self) -> None:
        path = os.path.join("app", "remediation", "policy.py")
        with open(path) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "executor" not in alias.name.lower()
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "executor" not in node.module.lower()

    def test_candidates_does_not_import_executor(self) -> None:
        path = os.path.join("app", "remediation", "candidates.py")
        with open(path) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "executor" not in alias.name.lower()
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    assert "executor" not in node.module.lower()


# Y. No shell/subprocess
class TestNoShell:
    def test_policy_no_subprocess(self) -> None:
        path = os.path.join("app", "remediation", "policy.py")
        with open(path) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "subprocess" not in alias.name.lower()
                    assert "os.system" not in alias.name.lower()

    def test_candidates_no_subprocess(self) -> None:
        path = os.path.join("app", "remediation", "candidates.py")
        with open(path) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "subprocess" not in alias.name.lower()
                    assert "os.system" not in alias.name.lower()

    def test_policy_no_shell_true(self) -> None:
        path = os.path.join("app", "remediation", "policy.py")
        with open(path) as f:
            content = f.read()
        assert "shell=True" not in content
        assert "shell = True" not in content

    def test_candidates_no_shell_true(self) -> None:
        path = os.path.join("app", "remediation", "candidates.py")
        with open(path) as f:
            content = f.read()
        assert "shell=True" not in content
        assert "shell = True" not in content


# Z. CandidatesSummary model
class TestCandidatesSummary:
    def test_summary_fields(self) -> None:
        s = CandidatesSummary(
            available_count=2,
            proposed_count=3,
            blocked_count=5,
            insufficient_evidence_count=1,
            stale_count=0,
            total_count=11,
            candidates=[],
        )
        assert s.available_count == 2
        assert s.total_count == 11

    def test_summary_is_frozen(self) -> None:
        s = CandidatesSummary()
        with pytest.raises(AttributeError):
            s.total_count = 99

    def test_summary_defaults(self) -> None:
        s = CandidatesSummary()
        assert s.available_count == 0
        assert s.total_count == 0
        assert s.candidates == []
