"""Phase 12.3 tests: HealthSessionRunner.

All tests use injected fake handlers and a fixed clock.  No real
discovery, analysis, filesystem, or database involvement.
"""

from __future__ import annotations

import ast
from pathlib import Path

from app.health.budgets import HealthBudgets
from app.health.models import (
    DataQuality,
    HealthStageStatus,
    HealthStageType,
)
from app.health.runner import (
    HealthSessionRunner,
    StageInvocation,
    StageOutcome,
    derive_data_quality,
    derive_session_status,
)

_FIXED_NOW = "2026-09-21T00:00:00+00:00"


def _ok_outcome(**overrides) -> StageOutcome:
    params: dict = {
        "ok": True,
        "data_quality": DataQuality.GOOD,
        "evidence_refs": ("discovery_run:16",),
        "provenance": {"source_type": "test", "source_id": "16"},
        "discovery_run_id": 16,
    }
    params.update(overrides)
    return StageOutcome(**params)


def _runner(**overrides):
    params: dict = {
        "profile": "quick",
        "store": object(),
        "session_id_factory": lambda: "hs_test_001",
        "utcnow": lambda: _FIXED_NOW,
        "monotonic_ms": lambda: 0,
    }
    params.update(overrides)
    return HealthSessionRunner(**params)


class TestQuickSession:
    def test_quick_runs_three_stages_in_order(self):
        order: list[str] = []

        def make(tag: str):
            def _handler(invocation: StageInvocation) -> StageOutcome:
                order.append(tag)
                return _ok_outcome(
                    provenance={"source_type": tag, "source_id": "16"}
                )

            return _handler

        runner = _runner(
            handlers={
                HealthStageType.DISCOVERY: make("discovery"),
                HealthStageType.ANALYSIS: make("analysis"),
                HealthStageType.CANDIDATES: make("candidates"),
            }
        )
        session = runner.run_session()

        assert order == ["discovery", "analysis", "candidates"]
        assert session.session_id == "hs_test_001"
        assert session.profile == "quick"
        assert session.status == HealthStageStatus.COMPLETED
        assert session.discovery_run_id == 16
        assert [s.stage_type for s in session.stages] == [
            HealthStageType.DISCOVERY,
            HealthStageType.ANALYSIS,
            HealthStageType.CANDIDATES,
        ]
        assert all(
            s.status == HealthStageStatus.COMPLETED for s in session.stages
        )

    def test_provenance_references_no_payloads(self):
        runner = _runner(
            handlers={
                stage: (lambda tag: (
                    lambda inv: _ok_outcome(
                        provenance={
                            "source_type": tag,
                            "source_id": "16",
                        }
                    )
                ))(stage.value)
                for stage in (
                    HealthStageType.DISCOVERY,
                    HealthStageType.ANALYSIS,
                    HealthStageType.CANDIDATES,
                )
            }
        )
        session = runner.run_session()
        for stage in session.stages:
            assert stage.provenance["session_id"] == "hs_test_001"
            assert "observed_at" in stage.provenance
        payload = session.to_dict()
        assert "payload" not in payload
        assert "snapshots" not in payload
        assert "findings" not in payload
        assert payload["discovery_run_id"] == 16


class TestStageIsolation:
    def test_analysis_failure_skips_candidates(self):
        def fail(invocation: StageInvocation) -> StageOutcome:
            raise RuntimeError("analyzer exploded")

        runner = _runner(
            handlers={
                HealthStageType.DISCOVERY: lambda inv: _ok_outcome(),
                HealthStageType.ANALYSIS: fail,
                HealthStageType.CANDIDATES: lambda inv: _ok_outcome(),
            }
        )
        session = runner.run_session()

        by_type = {s.stage_type: s for s in session.stages}
        assert by_type[HealthStageType.ANALYSIS].status == (
            HealthStageStatus.FAILED
        )
        assert "analyzer exploded" in (
            by_type[HealthStageType.ANALYSIS].error or ""
        )
        assert by_type[HealthStageType.CANDIDATES].status == (
            HealthStageStatus.SKIPPED
        )
        assert "prerequisite stage 'analysis'" in (
            by_type[HealthStageType.CANDIDATES].error or ""
        )
        assert session.status == HealthStageStatus.FAILED

    def test_candidates_failure_keeps_earlier_stages(self):
        def fail(invocation: StageInvocation) -> StageOutcome:
            raise RuntimeError("policy exploded")

        runner = _runner(
            handlers={
                HealthStageType.DISCOVERY: lambda inv: _ok_outcome(),
                HealthStageType.ANALYSIS: lambda inv: _ok_outcome(),
                HealthStageType.CANDIDATES: fail,
            }
        )
        session = runner.run_session()

        by_type = {s.stage_type: s for s in session.stages}
        assert by_type[HealthStageType.DISCOVERY].status == (
            HealthStageStatus.COMPLETED
        )
        assert by_type[HealthStageType.ANALYSIS].status == (
            HealthStageStatus.COMPLETED
        )
        assert by_type[HealthStageType.CANDIDATES].status == (
            HealthStageStatus.FAILED
        )
        assert session.status == HealthStageStatus.FAILED

    def test_discovery_failure_skips_dependents(self):
        def fail(invocation: StageInvocation) -> StageOutcome:
            raise RuntimeError("no evidence")

        runner = _runner(
            handlers={HealthStageType.DISCOVERY: fail},
        )
        session = runner.run_session()

        by_type = {s.stage_type: s for s in session.stages}
        assert by_type[HealthStageType.DISCOVERY].status == (
            HealthStageStatus.FAILED
        )
        assert by_type[HealthStageType.ANALYSIS].status == (
            HealthStageStatus.SKIPPED
        )
        assert by_type[HealthStageType.CANDIDATES].status == (
            HealthStageStatus.SKIPPED
        )
        assert session.status == HealthStageStatus.FAILED
        assert session.discovery_run_id is None


class TestUnimplementedStages:
    def test_requested_but_unhandled_stage_is_skipped(self):
        runner = _runner(
            profile="standard",
            handlers={
                HealthStageType.DISCOVERY: lambda inv: _ok_outcome(),
                HealthStageType.ANALYSIS: lambda inv: _ok_outcome(),
                HealthStageType.CANDIDATES: lambda inv: _ok_outcome(),
            },
        )
        session = runner.run_session()

        by_type = {s.stage_type: s for s in session.stages}
        assert by_type[HealthStageType.HISTORY].status == (
            HealthStageStatus.SKIPPED
        )
        assert "not implemented" in (
            by_type[HealthStageType.HISTORY].error or ""
        )
        assert session.status == HealthStageStatus.PARTIAL


class TestBudgets:
    def test_stage_overrun_becomes_budget_exceeded(self):
        ticks = iter([0, 5000])

        def slow(invocation: StageInvocation) -> StageOutcome:
            return _ok_outcome()

        runner = _runner(
            budgets=HealthBudgets(max_stage_runtime_ms=1000),
            monotonic_ms=lambda: next(ticks, 99999),
            handlers={
                HealthStageType.DISCOVERY: slow,
                HealthStageType.ANALYSIS: lambda inv: _ok_outcome(),
                HealthStageType.CANDIDATES: lambda inv: _ok_outcome(),
            },
        )
        session = runner.run_session()

        by_type = {s.stage_type: s for s in session.stages}
        assert by_type[HealthStageType.DISCOVERY].status == (
            HealthStageStatus.BUDGET_EXCEEDED
        )
        assert "max_stage_runtime_ms" in (
            by_type[HealthStageType.DISCOVERY].error or ""
        )

    def test_session_overrun_becomes_budget_exceeded(self):
        ticks = iter([0, 0, 0, 0, 0, 0, 0, 400000])

        runner = _runner(
            budgets=HealthBudgets(max_session_runtime_ms=60000),
            monotonic_ms=lambda: next(ticks, 400000),
            handlers={
                HealthStageType.DISCOVERY: lambda inv: _ok_outcome(),
                HealthStageType.ANALYSIS: lambda inv: _ok_outcome(),
                HealthStageType.CANDIDATES: lambda inv: _ok_outcome(),
            },
        )
        session = runner.run_session()
        assert session.status == HealthStageStatus.BUDGET_EXCEEDED


class TestStageContract:
    def test_timestamps_and_duration_recorded(self):
        runner = _runner(
            handlers={
                HealthStageType.DISCOVERY: lambda inv: _ok_outcome(),
                HealthStageType.ANALYSIS: lambda inv: _ok_outcome(),
                HealthStageType.CANDIDATES: lambda inv: _ok_outcome(),
            }
        )
        session = runner.run_session()

        assert session.started_at == _FIXED_NOW
        assert session.completed_at == _FIXED_NOW
        for stage in session.stages:
            assert stage.started_at == _FIXED_NOW
            assert stage.completed_at == _FIXED_NOW
            assert stage.duration_ms >= 0
            assert stage.evidence_timestamp == _FIXED_NOW

    def test_session_serialization_round_trip(self):
        import json

        from app.health.models import HealthSession

        runner = _runner(
            handlers={
                HealthStageType.DISCOVERY: lambda inv: _ok_outcome(),
                HealthStageType.ANALYSIS: lambda inv: _ok_outcome(),
                HealthStageType.CANDIDATES: lambda inv: _ok_outcome(),
            }
        )
        session = runner.run_session()
        restored = HealthSession.from_dict(session.to_dict())
        assert restored == session
        assert json.dumps(session.to_dict(), sort_keys=True) == json.dumps(
            restored.to_dict(), sort_keys=True
        )


class TestDerivation:
    def test_all_completed_is_completed(self):
        from app.health.models import HealthStage

        stages = tuple(
            HealthStage(
                stage_id=f"s:{t.value}",
                stage_type=t,
                status=HealthStageStatus.COMPLETED,
            )
            for t in (
                HealthStageType.DISCOVERY,
                HealthStageType.ANALYSIS,
                HealthStageType.CANDIDATES,
            )
        )
        assert derive_session_status(
            stages,
            (
                HealthStageType.DISCOVERY,
                HealthStageType.ANALYSIS,
                HealthStageType.CANDIDATES,
            ),
        ) == HealthStageStatus.COMPLETED

    def test_data_quality_good_when_all_good(self):
        from app.health.models import HealthStage

        stages = (
            HealthStage(
                stage_id="s:1",
                stage_type=HealthStageType.DISCOVERY,
                status=HealthStageStatus.COMPLETED,
                data_quality=DataQuality.GOOD,
            ),
        )
        assert derive_data_quality(
            HealthStageStatus.COMPLETED, stages
        ) == DataQuality.GOOD

    def test_data_quality_degraded_on_partial(self):
        from app.health.models import HealthStage

        stages = (
            HealthStage(
                stage_id="s:1",
                stage_type=HealthStageType.DISCOVERY,
                status=HealthStageStatus.COMPLETED,
                data_quality=DataQuality.GOOD,
            ),
        )
        assert derive_data_quality(
            HealthStageStatus.PARTIAL, stages
        ) == DataQuality.DEGRADED


class TestNoExecutionAuthority:
    def test_runner_has_no_remediation_methods(self):
        for name in (
            "execute",
            "execute_candidate",
            "remediate",
            "rollback",
            "quarantine",
        ):
            assert not hasattr(HealthSessionRunner, name)

    def test_no_forbidden_imports_in_health_package(self):
        package_dir = (
            Path(__file__).resolve().parent.parent / "app" / "health"
        )
        for path in sorted(package_dir.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    imported = [node.module or ""]
                else:
                    continue
                for name in imported:
                    assert "executor" not in name, f"{path.name} imports {name}"
                    assert "confirmation" not in name, (
                        f"{path.name} imports {name}"
                    )
                    assert "subprocess" not in name, (
                        f"{path.name} imports {name}"
                    )

    def test_no_dynamic_imports_in_health_package(self):
        package_dir = (
            Path(__file__).resolve().parent.parent / "app" / "health"
        )
        for path in sorted(package_dir.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Name) and func.id == "__import__":
                    raise AssertionError(
                        f"{path.name} uses __import__"
                    )
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "import_module"
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "importlib"
                ):
                    raise AssertionError(
                        f"{path.name} uses importlib.import_module"
                    )
