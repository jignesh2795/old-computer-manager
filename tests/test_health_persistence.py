"""Phase 12.6 tests: health session persistence.

Store tests use isolated SQLite files.  References only: no evidence
payloads are ever written to the health tables.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

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


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "health.db"
    SnapshotStore(path=str(path))
    return str(path)


@pytest.fixture
def store(db_path):
    return HealthSessionStore(db_path=db_path)


def _stage(stage_type: str = "discovery", **overrides) -> HealthStage:
    params: dict = {
        "stage_id": f"hs_test_001:{stage_type}",
        "stage_type": HealthStageType(stage_type),
        "status": HealthStageStatus.COMPLETED,
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


def _session(**overrides) -> HealthSession:
    params: dict = {
        "session_id": "hs_test_001",
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
    return HealthSession(**params)


class TestCreateSession:
    def test_create_and_reload(self, store):
        store.create_session(_session())
        loaded = store.get_session("hs_test_001")
        assert loaded is not None
        assert loaded.session_id == "hs_test_001"
        assert loaded.profile == "quick"
        assert loaded.status == HealthStageStatus.COMPLETED

    def test_profile_budgets_timestamps_quality_persisted(self, store):
        budgets = HealthBudgets(max_history_runs=7).to_dict()
        store.create_session(
            _session(budgets=budgets, data_quality=DataQuality.DEGRADED)
        )
        loaded = store.get_session("hs_test_001")
        assert loaded is not None
        assert loaded.budgets["max_history_runs"] == 7
        assert loaded.created_at == _FIXED_NOW
        assert loaded.started_at == _FIXED_NOW
        assert loaded.completed_at == _FIXED_NOW
        assert loaded.data_quality == DataQuality.DEGRADED

    def test_discovery_run_and_evidence_ids_persisted(self, store):
        store.create_session(_session())
        loaded = store.get_session("hs_test_001")
        assert loaded is not None
        assert loaded.discovery_run_id == 16
        assert loaded.evidence_ids == ("discovery_run:16",)

    def test_duplicate_session_rejected(self, store):
        store.create_session(_session())
        with pytest.raises(sqlite3.IntegrityError):
            store.create_session(_session())

    def test_unknown_session_returns_none(self, store):
        assert store.get_session("hs_missing") is None


class TestSaveStage:
    def test_stage_round_trip(self, store):
        store.create_session(_session())
        stage = _stage(error=None)
        store.save_stage("hs_test_001", stage)
        stages = store.get_stages("hs_test_001")
        assert len(stages) == 1
        assert stages[0] == stage

    def test_stage_timing_error_evidence_persisted(self, store):
        store.create_session(_session())
        stage = _stage(
            "analysis",
            status=HealthStageStatus.FAILED,
            duration_ms=250,
            error="analyzer exploded",
            evidence_timestamp=_FIXED_NOW,
        )
        store.save_stage("hs_test_001", stage)
        (loaded,) = store.get_stages("hs_test_001")
        assert loaded.duration_ms == 250
        assert loaded.error == "analyzer exploded"
        assert loaded.evidence_timestamp == _FIXED_NOW
        assert loaded.status == HealthStageStatus.FAILED

    def test_duplicate_stage_upsert_is_deterministic(self, store):
        store.create_session(_session())
        store.save_stage("hs_test_001", _stage())
        store.save_stage(
            "hs_test_001", _stage(error="second write wins")
        )
        stages = store.get_stages("hs_test_001")
        assert len(stages) == 1
        assert stages[0].error == "second write wins"

    def test_invalid_session_fk_rejected(self, store):
        with pytest.raises(sqlite3.IntegrityError):
            store.save_stage("hs_missing", _stage())


class TestFinalize:
    def test_finalize_updates_status(self, store):
        store.create_session(_session(status=HealthStageStatus.RUNNING))
        store.finalize_session(_session())
        loaded = store.get_session("hs_test_001")
        assert loaded is not None
        assert loaded.status == HealthStageStatus.COMPLETED

    def test_finalize_unknown_session_rejected(self, store):
        with pytest.raises(ValueError, match="unknown session"):
            store.finalize_session(_session(session_id="hs_missing"))


class TestRoundTrip:
    def test_full_session_round_trip(self, store):
        session = _session(
            stages=(
                _stage("discovery"),
                _stage("analysis"),
                _stage("candidates"),
            )
        )
        store.create_session(session)
        for stage in session.stages:
            store.save_stage(session.session_id, stage)
        store.finalize_session(session)

        loaded = store.get_session("hs_test_001")
        assert loaded is not None
        assert loaded.to_dict() == session.to_dict()

    def test_no_payload_duplication(self, db_path, store):
        session = _session(
            stages=(_stage("discovery"),),
            evidence_ids=("discovery_run:16", "finding:42"),
        )
        store.create_session(session)
        store.save_stage(session.session_id, session.stages[0])

        connection = sqlite3.connect(db_path)
        try:
            texts = []
            for table in ("health_sessions", "health_stages"):
                for row in connection.execute(f"SELECT * FROM {table}"):
                    texts.extend(str(value) for value in row if value)
        finally:
            connection.close()
        blob = " ".join(texts)
        assert "payload_json" not in blob
        assert "snapshots" not in blob
        assert "findings" not in blob

    def test_evidence_ids_stay_references(self, store):
        store.create_session(_session())
        loaded = store.get_session("hs_test_001")
        assert loaded is not None
        assert loaded.evidence_ids == ("discovery_run:16",)
        for ref in loaded.evidence_ids:
            assert isinstance(ref, str)
            assert "{" not in ref

    def test_unknown_enum_is_controlled_error(self, db_path, store):
        store.create_session(_session())
        connection = sqlite3.connect(db_path)
        try:
            connection.execute(
                "UPDATE health_sessions SET status = 'vibing'"
                " WHERE session_id = 'hs_test_001'"
            )
            connection.commit()
        finally:
            connection.close()
        with pytest.raises(ValueError):
            store.get_session("hs_test_001")


class TestListSessions:
    def test_list_sessions(self, store):
        store.create_session(_session(session_id="hs_a"))
        store.create_session(_session(session_id="hs_b"))
        sessions = store.list_sessions()
        assert [s.session_id for s in sessions] == ["hs_b", "hs_a"]

    def test_list_sessions_limit(self, store):
        for i in range(3):
            store.create_session(_session(session_id=f"hs_{i}"))
        assert len(store.list_sessions(limit=2)) == 2


class TestRunnerPersistence:
    def _quick_runner(self, session_store, **overrides):
        from app.health.runner import HealthSessionRunner, StageOutcome

        def ok(tag):
            def _handler(invocation):
                return StageOutcome(
                    ok=True,
                    data_quality=DataQuality.GOOD,
                    evidence_refs=("discovery_run:16",),
                    provenance={"source_type": tag, "source_id": "16"},
                    discovery_run_id=16,
                )

            return _handler

        params: dict = {
            "profile": "quick",
            "store": object(),
            "session_store": session_store,
            "session_id_factory": lambda: "hs_run_001",
            "utcnow": lambda: _FIXED_NOW,
            "monotonic_ms": lambda: 0,
            "handlers": {
                HealthStageType.DISCOVERY: ok("discovery"),
                HealthStageType.ANALYSIS: ok("analysis"),
                HealthStageType.CANDIDATES: ok("candidates"),
            },
        }
        params.update(overrides)
        return HealthSessionRunner(**params)

    def test_runner_persists_session_and_stages(self, store):
        runner = self._quick_runner(store)
        session = runner.run_session()

        assert session.status == HealthStageStatus.COMPLETED
        assert runner.last_persistence_errors == []
        loaded = store.get_session("hs_run_001")
        assert loaded is not None
        assert loaded.to_dict() == session.to_dict()
        assert len(store.get_stages("hs_run_001")) == 3

    def test_persistence_failure_preserves_stage_results(self):
        from unittest.mock import MagicMock

        failing = MagicMock()
        failing.create_session.side_effect = OSError("disk gone")
        failing.save_stage.side_effect = OSError("disk gone")
        failing.finalize_session.side_effect = OSError("disk gone")

        runner = self._quick_runner(failing)
        session = runner.run_session()

        assert session.status == HealthStageStatus.COMPLETED
        assert [s.status for s in session.stages] == [
            HealthStageStatus.COMPLETED,
        ] * 3
        assert runner.last_persistence_errors != []
        assert any(
            "create_session" in err
            for err in runner.last_persistence_errors
        )
