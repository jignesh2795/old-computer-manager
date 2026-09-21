"""Phase 12.7 tests: persisted session inspection CLI.

Uses a real HealthSessionStore on an isolated database, seeded through
the store API.  The CLI under test only reads persisted state.
"""

from __future__ import annotations

import ast
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from app.cli import main
from app.database.sqlite import SnapshotStore
from app.health.budgets import HealthBudgets
from app.health.models import (
    DataQuality,
    HealthSession,
    HealthStage,
    HealthStageStatus,
    HealthStageType,
)
from app.health.persistence import HealthSessionStore

_FIXED_NOW = "2026-09-21T00:00:00+00:00"


def _stage(stage_type, status="completed", **overrides):
    params = {
        "stage_id": f"hs_test_001:{stage_type}",
        "stage_type": HealthStageType(stage_type),
        "status": HealthStageStatus(status),
        "started_at": _FIXED_NOW,
        "completed_at": _FIXED_NOW,
        "duration_ms": 100,
        "evidence_timestamp": _FIXED_NOW,
        "data_quality": DataQuality.GOOD,
        "provenance": {"source_type": stage_type, "source_id": "16"},
        "evidence_refs": ("discovery_run:16",),
    }
    params.update(overrides)
    return HealthStage(**params)


def _seeded_store(tmp_path, session_id="hs_test_001", **overrides):
    db_path = str(tmp_path / "inspect.db")
    SnapshotStore(path=db_path)
    store = HealthSessionStore(db_path=db_path)
    params = {
        "session_id": session_id,
        "profile": "quick",
        "created_at": _FIXED_NOW,
        "started_at": _FIXED_NOW,
        "completed_at": _FIXED_NOW,
        "status": HealthStageStatus.COMPLETED,
        "stages": (),
        "budgets": HealthBudgets().to_dict(),
        "data_quality": DataQuality.GOOD,
        "discovery_run_id": 16,
        "evidence_ids": ("discovery_run:16",),
    }
    params.update(overrides)
    session = HealthSession(**params)
    store.create_session(session)
    for stage in session.stages:
        store.save_stage(session_id, stage)
    return store


def _session_with_stages(**overrides):
    params: dict = {
        "stages": (
            _stage("discovery"),
            _stage("analysis"),
            _stage("candidates"),
        )
    }
    params.update(overrides)
    return params


def _run_main(argv, store):
    with (
        patch.object(sys, "argv", argv),
        patch("app.cli._health_store", return_value=store),
        redirect_stdout(io.StringIO()) as out,
    ):
        code = main()
    return code, out.getvalue()


class TestSessionsCommand:
    def test_command_exists_and_lists(self, tmp_path):
        store = _seeded_store(tmp_path, **_session_with_stages())
        code, output = _run_main(["prog", "health", "sessions"], store)
        assert code == 0
        assert "Health Sessions" in output
        assert "hs_test_001" in output
        assert "quick" in output
        assert "completed" in output

    def test_empty_database_handled_cleanly(self, tmp_path):
        db_path = str(tmp_path / "empty.db")
        SnapshotStore(path=db_path)
        store = HealthSessionStore(db_path=db_path)
        code, output = _run_main(["prog", "health", "sessions"], store)
        assert code == 0
        assert "No health sessions found." in output

    def test_missing_tables_handled_cleanly(self, tmp_path):
        store = HealthSessionStore(db_path=str(tmp_path / "fresh.db"))
        code, output = _run_main(["prog", "health", "sessions"], store)
        assert code == 0
        assert "No health sessions found." in output

    def test_json_output(self, tmp_path):
        store = _seeded_store(tmp_path, **_session_with_stages())
        code, output = _run_main(
            ["prog", "health", "sessions", "--json"], store
        )
        assert code == 0
        payload = json.loads(output.split("\n", 1)[1])
        assert isinstance(payload, list)
        assert payload[0]["session_id"] == "hs_test_001"
        assert payload[0]["stage_count"] == 3
        assert payload[0]["discovery_run_id"] == 16
        assert "payload" not in json.dumps(payload)


class TestSessionCommand:
    def test_session_lookup(self, tmp_path):
        store = _seeded_store(tmp_path, **_session_with_stages())
        code, output = _run_main(
            ["prog", "health", "session", "hs_test_001"], store
        )
        assert code == 0
        assert "hs_test_001" in output
        assert "discovery" in output
        assert "discovery_run_id: 16" in output
        assert "evidence_ids:     1" in output

    def test_unknown_session(self, tmp_path):
        store = _seeded_store(tmp_path)
        code, output = _run_main(
            ["prog", "health", "session", "hs_missing"], store
        )
        assert code == 1
        assert "not found" in output

    def test_session_json(self, tmp_path):
        store = _seeded_store(tmp_path, **_session_with_stages())
        code, output = _run_main(
            ["prog", "health", "session", "hs_test_001", "--json"], store
        )
        assert code == 0
        payload = json.loads(output.split("\n", 1)[1])
        assert payload["session_id"] == "hs_test_001"
        assert len(payload["stages"]) == 3
        assert payload["discovery_run_id"] == 16


class TestStagesCommand:
    def test_stage_lookup(self, tmp_path):
        store = _seeded_store(tmp_path, **_session_with_stages())
        code, output = _run_main(
            ["prog", "health", "stages", "hs_test_001"], store
        )
        assert code == 0
        assert "Stage: discovery" in output
        assert "Stage: analysis" in output
        assert "Stage: candidates" in output
        assert "Duration: 0.10s" in output
        assert "Evidence IDs: ['discovery_run:16']" in output

    def test_unknown_session_stages(self, tmp_path):
        store = _seeded_store(tmp_path)
        code, output = _run_main(
            ["prog", "health", "stages", "hs_missing"], store
        )
        assert code == 1
        assert "not found" in output

    def test_failed_skipped_budget_stages(self, tmp_path):
        store = _seeded_store(
            tmp_path,
            status=HealthStageStatus.PARTIAL,
            stages=(
                _stage("discovery", "failed", error="boom"),
                _stage(
                    "analysis",
                    "skipped",
                    duration_ms=0,
                    error="Skipped because prerequisite stage "
                    "'discovery' did not complete.",
                ),
                _stage(
                    "candidates",
                    "budget_exceeded",
                    duration_ms=5000,
                    error="stage exceeded max_stage_runtime_ms",
                ),
            ),
        )
        code, output = _run_main(
            ["prog", "health", "stages", "hs_test_001"], store
        )
        assert code == 0
        assert "Status: failed" in output
        assert "boom" in output
        assert "Status: skipped" in output
        assert "prerequisite stage" in output
        assert "Status: budget_exceeded" in output
        assert "max_stage_runtime_ms" in output

    def test_stages_json(self, tmp_path):
        store = _seeded_store(tmp_path, **_session_with_stages())
        code, output = _run_main(
            ["prog", "health", "stages", "hs_test_001", "--json"], store
        )
        assert code == 0
        payload = json.loads(output.split("\n", 1)[1])
        assert [s["stage_type"] for s in payload] == [
            "discovery",
            "analysis",
            "candidates",
        ]


class TestPreservation:
    def test_timestamps_duration_quality_refs_preserved(self, tmp_path):
        store = _seeded_store(tmp_path, **_session_with_stages())
        code, output = _run_main(
            ["prog", "health", "stages", "hs_test_001", "--json"], store
        )
        assert code == 0
        payload = json.loads(output.split("\n", 1)[1])
        stage = payload[0]
        assert stage["started_at"] == _FIXED_NOW
        assert stage["completed_at"] == _FIXED_NOW
        assert stage["duration_ms"] == 100
        assert stage["data_quality"] == "good"
        assert stage["evidence_refs"] == ["discovery_run:16"]

    def test_no_payloads_emitted(self, tmp_path):
        store = _seeded_store(tmp_path, **_session_with_stages())
        for argv in (
            ["prog", "health", "sessions", "--json"],
            ["prog", "health", "session", "hs_test_001", "--json"],
            ["prog", "health", "stages", "hs_test_001", "--json"],
        ):
            code, output = _run_main(argv, store)
            assert code == 0
            assert "payload_json" not in output
            assert "snapshots" not in output


class TestReadOnly:
    def test_inspection_invokes_nothing(self):
        source = (
            Path(__file__).resolve().parent.parent / "app" / "cli.py"
        ).read_text(encoding="utf-8")
        bodies = ""
        for name in (
            "def cmd_health_sessions",
            "def cmd_health_session",
            "def cmd_health_stages",
        ):
            start = source.index(name)
            end = source.index("\ndef ", start)
            bodies += source[start:end]
        for forbidden in (
            "run_session",
            "HealthSessionRunner",
            "analyze_latest_run",
            "run_discovery",
            "build_health_report",
            "evaluate_candidates",
            "executor",
            "confirmation",
            "diagnostics",
        ):
            assert forbidden not in bodies, forbidden
        tree = ast.parse(bodies)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                assert "executor" not in name
                assert "subprocess" not in name

    def test_existing_health_run_still_works(self, tmp_path):
        from unittest.mock import MagicMock

        runner_cls = MagicMock()
        runner_cls.return_value.run_session.return_value = HealthSession(
            session_id="hs_run_001",
            profile="quick",
            created_at=_FIXED_NOW,
            started_at=_FIXED_NOW,
            completed_at=_FIXED_NOW,
            status=HealthStageStatus.COMPLETED,
            stages=(),
            budgets={},
            data_quality=DataQuality.GOOD,
        )
        runner_cls.return_value.last_persistence_errors = []
        with (
            patch.object(sys, "argv", ["prog", "health", "run"]),
            patch(
                "app.health.runner.HealthSessionRunner", runner_cls
            ),
            redirect_stdout(io.StringIO()),
        ):
            assert main() == 0
        assert runner_cls.call_count == 1
