"""Phase 12.5 tests: `health run` CLI slice.

The runner is mocked: these tests cover the thin CLI adapter only
(parsing, output contracts, exit codes).  No real subsystems run.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

from app.cli import main
from app.health.models import (
    DataQuality,
    HealthSession,
    HealthStage,
    HealthStageStatus,
    HealthStageType,
)


def _stage(
    stage_id: str,
    stage_type,
    status,
    duration_ms: int = 100,
    error=None,
):
    return HealthStage(
        stage_id=stage_id,
        stage_type=HealthStageType(stage_type),
        status=HealthStageStatus(status),
        started_at="2026-09-21T00:00:00+00:00",
        completed_at="2026-09-21T00:00:01+00:00",
        duration_ms=duration_ms,
        error=error,
        evidence_timestamp="2026-09-21T00:00:01+00:00",
        data_quality=DataQuality.GOOD,
        provenance={"session_id": "hs_test_001"},
        evidence_refs=("discovery_run:16",),
    )


def _completed_session() -> HealthSession:
    return HealthSession(
        session_id="hs_test_001",
        profile="quick",
        created_at="2026-09-21T00:00:00+00:00",
        started_at="2026-09-21T00:00:00+00:00",
        completed_at="2026-09-21T00:00:01+00:00",
        status=HealthStageStatus.COMPLETED,
        stages=(
            _stage("hs:discovery", "discovery", "completed"),
            _stage("hs:analysis", "analysis", "completed"),
            _stage("hs:candidates", "candidates", "completed"),
        ),
        budgets={"max_session_runtime_ms": 300000},
        data_quality=DataQuality.GOOD,
        discovery_run_id=16,
        evidence_ids=("discovery_run:16",),
    )


def _run_main(argv: list[str], session) -> tuple[int, str]:
    runner_cls = MagicMock()
    runner_cls.return_value.run_session.return_value = session
    runner_cls.return_value.last_persistence_errors = []
    with (
        patch.object(sys, "argv", argv),
        patch("app.health.runner.HealthSessionRunner", runner_cls),
        redirect_stdout(io.StringIO()) as out,
    ):
        code = main()
    return code, out.getvalue()


class TestCommandExists:
    def test_health_run_runs_runner_once(self):
        session = _completed_session()
        runner_cls = MagicMock()
        runner_cls.return_value.run_session.return_value = session
        with (
            patch.object(
                sys, "argv", ["prog", "health", "run", "--profile", "quick"]
            ),
            patch("app.health.runner.HealthSessionRunner", runner_cls),
            redirect_stdout(io.StringIO()),
        ):
            assert main() == 0
        assert runner_cls.call_count == 1
        assert runner_cls.return_value.run_session.call_count == 1

    def test_default_profile_is_quick(self):
        session = _completed_session()
        runner_cls = MagicMock()
        runner_cls.return_value.run_session.return_value = session
        with (
            patch.object(sys, "argv", ["prog", "health", "run"]),
            patch("app.health.runner.HealthSessionRunner", runner_cls),
            redirect_stdout(io.StringIO()),
        ):
            assert main() == 0
        _, kwargs = runner_cls.call_args
        assert kwargs.get("profile", "quick") == "quick"

    def test_cli_passes_session_store(self):
        session = _completed_session()
        runner_cls = MagicMock()
        runner_cls.return_value.run_session.return_value = session
        runner_cls.return_value.last_persistence_errors = []
        with (
            patch.object(sys, "argv", ["prog", "health", "run"]),
            patch("app.health.runner.HealthSessionRunner", runner_cls),
            redirect_stdout(io.StringIO()),
        ):
            assert main() == 0
        _, kwargs = runner_cls.call_args
        assert "session_store" in kwargs


class TestUnknownProfile:
    def test_unknown_profile_rejected(self):
        runner_cls = MagicMock()
        with (
            patch.object(
                sys, "argv", ["prog", "health", "run", "--profile", "nonsense"]
            ),
            patch("app.health.runner.HealthSessionRunner", runner_cls),
            redirect_stdout(io.StringIO()) as out,
        ):
            code = main()
        assert code == 2
        assert "Unknown profile" in out.getvalue()
        assert runner_cls.call_count == 0


class TestJsonOutput:
    def test_json_contract(self):
        code, output = _run_main(
            ["prog", "health", "run", "--profile", "quick", "--json"],
            _completed_session(),
        )
        assert code == 0
        payload = json.loads(output.split("\n", 1)[1])
        assert payload["session_id"] == "hs_test_001"
        assert payload["profile"] == "quick"
        assert payload["status"] == "completed"
        assert len(payload["stages"]) == 3
        assert payload["data_quality"] == "good"
        assert payload["discovery_run_id"] == 16
        assert "payload" not in payload
        assert "snapshots" not in payload
        assert "findings" not in payload


class TestHumanOutput:
    def test_human_readable_output(self):
        code, output = _run_main(
            ["prog", "health", "run", "--profile", "quick"],
            _completed_session(),
        )
        assert code == 0
        assert "Health Session" in output
        assert "hs_test_001" in output
        assert "[OK] discovery" in output
        assert "[OK] analysis" in output
        assert "[OK] candidates" in output

    def test_skipped_stage_rendering(self):
        session = HealthSession(
            session_id="hs_test_002",
            profile="standard",
            created_at="2026-09-21T00:00:00+00:00",
            started_at="2026-09-21T00:00:00+00:00",
            completed_at="2026-09-21T00:00:01+00:00",
            status=HealthStageStatus.PARTIAL,
            stages=(
                _stage("hs:discovery", "discovery", "completed"),
                _stage("hs:analysis", "analysis", "completed"),
                _stage(
                    "hs:history",
                    "history",
                    "skipped",
                    duration_ms=0,
                    error="Skipped: no runner handler (not implemented).",
                ),
                _stage("hs:candidates", "candidates", "completed"),
            ),
            budgets={},
            data_quality=DataQuality.DEGRADED,
            discovery_run_id=16,
            evidence_ids=("discovery_run:16",),
        )
        code, output = _run_main(
            ["prog", "health", "run", "--profile", "standard"], session
        )
        assert code == 0
        assert "[SKIPPED] history" in output
        assert "no runner handler" in output

    def test_budget_exceeded_rendering(self):
        session = HealthSession(
            session_id="hs_test_003",
            profile="quick",
            created_at="2026-09-21T00:00:00+00:00",
            started_at="2026-09-21T00:00:00+00:00",
            completed_at="2026-09-21T00:00:01+00:00",
            status=HealthStageStatus.PARTIAL,
            stages=(
                _stage(
                    "hs:discovery",
                    "discovery",
                    "budget_exceeded",
                    duration_ms=5000,
                    error="stage exceeded max_stage_runtime_ms",
                ),
                _stage("hs:analysis", "analysis", "skipped", duration_ms=0),
                _stage("hs:candidates", "candidates", "skipped", duration_ms=0),
            ),
            budgets={},
            data_quality=DataQuality.DEGRADED,
            discovery_run_id=None,
            evidence_ids=(),
        )
        code, output = _run_main(
            ["prog", "health", "run", "--profile", "quick"], session
        )
        assert "[BUDGET] discovery" in output
        assert "max_stage_runtime_ms" in output


class TestExitCodes:
    def test_failed_session_exits_nonzero(self):
        session = HealthSession(
            session_id="hs_test_004",
            profile="quick",
            created_at="2026-09-21T00:00:00+00:00",
            started_at="2026-09-21T00:00:00+00:00",
            completed_at="2026-09-21T00:00:01+00:00",
            status=HealthStageStatus.FAILED,
            stages=(
                _stage("hs:discovery", "discovery", "failed",
                       error="discovery failed: boom"),
                _stage("hs:analysis", "analysis", "skipped", duration_ms=0),
                _stage("hs:candidates", "candidates", "skipped", duration_ms=0),
            ),
            budgets={},
            data_quality=DataQuality.DEGRADED,
            discovery_run_id=None,
            evidence_ids=(),
        )
        code, output = _run_main(
            ["prog", "health", "run", "--profile", "quick"], session
        )
        assert code == 1
        assert "boom" in output


class TestNoBusinessLogicDuplication:
    def test_cli_contains_no_subsystem_calls(self):
        import inspect
        from pathlib import Path

        source = Path("app/cli.py").read_text(encoding="utf-8")
        start = source.index("def cmd_health_run")
        end = source.index("\ndef main", start)
        body = source[start:end]
        assert "run_discovery" not in body
        assert "analyze_latest_run" not in body
        assert "build_health_report" not in body
        assert "evaluate_candidates" not in body
        assert "HealthSessionRunner" in body
        assert "import" in body  # lazy imports only

    def test_cli_has_no_executor_paths(self):
        from pathlib import Path

        source = Path("app/cli.py").read_text(encoding="utf-8")
        start = source.index("def cmd_health_run")
        end = source.index("\ndef main", start)
        body = source[start:end]
        assert "executor" not in body
        assert "confirmation" not in body
