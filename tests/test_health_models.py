"""Phase 12.1 tests: HealthSession domain contract.

Focused unit tests for app/health/models.py.  No filesystem mutation,
no database, no executor involvement.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.health.models import (
    TERMINAL_STATUSES,
    DataQuality,
    HealthSession,
    HealthStage,
    HealthStageStatus,
    HealthStageType,
    is_legal_transition,
    transition_stage,
)


def _make_stage(**overrides) -> HealthStage:
    params = {
        "stage_id": "stage:discovery:1",
        "stage_type": HealthStageType.DISCOVERY,
    }
    params.update(overrides)
    return HealthStage(**params)


def _make_session(**overrides) -> HealthSession:
    params = {
        "session_id": "hs_test_001",
        "profile": "quick",
        "created_at": "2026-09-21T00:00:00+00:00",
    }
    params.update(overrides)
    return HealthSession(**params)


class TestStageTypes:
    def test_all_expected_stage_types(self):
        values = {t.value for t in HealthStageType}
        assert values == {
            "discovery",
            "analysis",
            "history",
            "diagnostics",
            "ai",
            "candidates",
        }


class TestStageStatuses:
    def test_all_expected_statuses(self):
        values = {s.value for s in HealthStageStatus}
        assert values == {
            "pending",
            "running",
            "completed",
            "partial",
            "failed",
            "skipped",
            "budget_exceeded",
            "stale",
        }

    def test_terminal_statuses_have_no_outgoing(self):
        for status in TERMINAL_STATUSES:
            for candidate in HealthStageStatus:
                assert not is_legal_transition(status, candidate)


class TestTransitions:
    def test_pending_to_running(self):
        stage = _make_stage()
        moved = transition_stage(stage, HealthStageStatus.RUNNING)
        assert moved.status == HealthStageStatus.RUNNING
        assert stage.status == HealthStageStatus.PENDING

    def test_running_to_completed(self):
        stage = _make_stage(status=HealthStageStatus.RUNNING)
        moved = transition_stage(
            stage,
            HealthStageStatus.COMPLETED,
            completed_at="2026-09-21T00:00:01+00:00",
            duration_ms=1000,
        )
        assert moved.status == HealthStageStatus.COMPLETED
        assert moved.duration_ms == 1000

    def test_running_to_budget_exceeded(self):
        stage = _make_stage(status=HealthStageStatus.RUNNING)
        moved = transition_stage(
            stage,
            HealthStageStatus.BUDGET_EXCEEDED,
            error="stage exceeded max_stage_runtime_ms",
        )
        assert moved.status == HealthStageStatus.BUDGET_EXCEEDED
        assert "max_stage_runtime_ms" in (moved.error or "")

    def test_pending_to_completed_is_illegal(self):
        stage = _make_stage()
        with pytest.raises(ValueError, match="Illegal stage transition"):
            transition_stage(stage, HealthStageStatus.COMPLETED)

    def test_completed_is_terminal(self):
        stage = _make_stage(status=HealthStageStatus.COMPLETED)
        with pytest.raises(ValueError, match="Illegal stage transition"):
            transition_stage(stage, HealthStageStatus.RUNNING)

    def test_invalid_status_rejected(self):
        stage = _make_stage()
        with pytest.raises(ValueError, match="Invalid status"):
            transition_stage(stage, "done")  # type: ignore[arg-type]


class TestSerialization:
    def test_stage_round_trip(self):
        stage = _make_stage(
            status=HealthStageStatus.RUNNING,
            started_at="2026-09-21T00:00:00+00:00",
            evidence_timestamp="2026-09-21T00:00:00+00:00",
            data_quality=DataQuality.GOOD,
            provenance={"source_type": "discovery", "source_id": "16"},
            evidence_refs=("run:16",),
        )
        restored = HealthStage.from_dict(stage.to_dict())
        assert restored == stage

    def test_session_round_trip(self):
        session = _make_session(
            status=HealthStageStatus.RUNNING,
            stages=(_make_stage(),),
            budgets={"max_session_runtime_ms": 60000},
            discovery_run_id=16,
            evidence_ids=("run:16",),
        )
        restored = HealthSession.from_dict(session.to_dict())
        assert restored == session

    def test_serialization_is_deterministic(self):
        session = _make_session(
            stages=(_make_stage(), _make_stage(stage_id="s2")),
        )
        first = json.dumps(session.to_dict(), sort_keys=True)
        second = json.dumps(
            HealthSession.from_dict(session.to_dict()).to_dict(),
            sort_keys=True,
        )
        assert first == second

    def test_unknown_enum_rejected(self):
        with pytest.raises(ValueError):
            HealthStage.from_dict(
                _make_stage().to_dict() | {"status": "nope"}
            )

    def test_session_references_evidence_only(self):
        session = _make_session(discovery_run_id=16)
        payload = session.to_dict()
        assert payload["discovery_run_id"] == 16
        assert "payload" not in payload
        assert "snapshots" not in payload
        assert "findings" not in payload


class TestValidation:
    def test_negative_duration_rejected(self):
        with pytest.raises(ValueError, match="duration_ms"):
            _make_stage(duration_ms=-1)

    def test_negative_budget_rejected(self):
        with pytest.raises(ValueError, match="Budget"):
            _make_session(budgets={"max_session_runtime_ms": -1})


class TestSafetyBoundaries:
    def _imported_modules(self, path: Path) -> list[str]:
        import ast

        tree = ast.parse(path.read_text(encoding="utf-8"))
        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    names.append(node.module)
        return names

    def test_no_forbidden_imports_in_health_package(self):
        package_dir = Path(__file__).resolve().parent.parent / "app" / "health"
        forbidden = ("executor", "confirmation", "subprocess")
        for path in sorted(package_dir.glob("*.py")):
            for imported in self._imported_modules(path):
                for name in forbidden:
                    assert name not in imported, (
                        f"{path.name} imports {imported}"
                    )

    def test_models_module_has_no_dangerous_imports(self):
        import app.health.models as models

        source_path = Path(models.__file__)
        for imported in self._imported_modules(source_path):
            assert "subprocess" not in imported
            assert "executor" not in imported
            assert "confirmation" not in imported
