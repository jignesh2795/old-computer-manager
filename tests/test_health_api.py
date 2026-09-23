"""Phase 12.9 tests: read-only health session API.

Uses TestClient with dependency overrides; tests never touch the real
database and never trigger discovery, analysis, or remediation.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.api import dependencies
from app.api.app import create_app
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


def _make_client(tmp_path, sessions=()):
    db_path = str(tmp_path / "api.db")
    snapshot = SnapshotStore(path=db_path)
    store = HealthSessionStore(db_path=db_path)
    for session in sessions:
        store.create_session(session)
        for stage in session.stages:
            store.save_stage(session.session_id, stage)
    app = create_app()
    app.dependency_overrides[dependencies.get_store] = lambda: snapshot
    return TestClient(app), store


def _session(session_id="hs_test_001", **overrides):
    params = {
        "session_id": session_id,
        "profile": "quick",
        "created_at": _FIXED_NOW,
        "started_at": _FIXED_NOW,
        "completed_at": _FIXED_NOW,
        "status": HealthStageStatus.COMPLETED,
        "stages": (
            _stage("discovery"),
            _stage("analysis"),
            _stage("candidates"),
        ),
        "budgets": HealthBudgets().to_dict(),
        "data_quality": DataQuality.GOOD,
        "discovery_run_id": 16,
        "evidence_ids": ("discovery_run:16",),
    }
    params.update(overrides)
    return HealthSession(**params)


class TestListSessions:
    def test_list_empty(self, tmp_path):
        client, _ = _make_client(tmp_path)
        response = client.get("/api/v1/health/sessions")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_persisted_sessions(self, tmp_path):
        client, _ = _make_client(
            tmp_path, sessions=[_session(), _session("hs_test_002")]
        )
        response = client.get("/api/v1/health/sessions")
        assert response.status_code == 200
        payload = response.json()
        assert [s["session_id"] for s in payload] == [
            "hs_test_002",
            "hs_test_001",
        ]
        assert payload[0]["stage_count"] == 3
        assert payload[0]["discovery_run_id"] == 16

    def test_limit_handling(self, tmp_path):
        client, _ = _make_client(
            tmp_path,
            sessions=[_session(f"hs_{i}") for i in range(3)],
        )
        response = client.get("/api/v1/health/sessions?limit=2")
        assert response.status_code == 200
        assert len(response.json()) == 2

    def test_limit_rejected_when_out_of_range(self, tmp_path):
        client, _ = _make_client(tmp_path)
        assert client.get("/api/v1/health/sessions?limit=0").status_code == 422
        assert client.get("/api/v1/health/sessions?limit=101").status_code == 422


class TestSessionDetail:
    def test_session_detail(self, tmp_path):
        client, _ = _make_client(tmp_path, sessions=[_session()])
        response = client.get("/api/v1/health/sessions/hs_test_001")
        assert response.status_code == 200
        payload = response.json()
        assert payload["profile"] == "quick"
        assert payload["status"] == "completed"
        assert len(payload["stages"]) == 3
        assert payload["discovery_run_id"] == 16
        assert payload["evidence_ids"] == ["discovery_run:16"]
        assert "max_history_runs" in payload["budgets"]

    def test_unknown_session_404(self, tmp_path):
        client, _ = _make_client(tmp_path)
        response = client.get("/api/v1/health/sessions/hs_missing")
        assert response.status_code == 404


class TestStageDetail:
    def test_stage_detail(self, tmp_path):
        client, _ = _make_client(tmp_path, sessions=[_session()])
        response = client.get("/api/v1/health/sessions/hs_test_001/stages")
        assert response.status_code == 200
        payload = response.json()
        assert payload["session_id"] == "hs_test_001"
        assert [s["stage_type"] for s in payload["stages"]] == [
            "discovery",
            "analysis",
            "candidates",
        ]
        stage = payload["stages"][0]
        assert stage["status"] == "completed"
        assert stage["duration_ms"] == 100
        assert stage["data_quality"] == "good"
        assert stage["evidence_refs"] == ["discovery_run:16"]

    def test_unknown_session_stages_404(self, tmp_path):
        client, _ = _make_client(tmp_path)
        response = client.get("/api/v1/health/sessions/hs_missing/stages")
        assert response.status_code == 404

    def test_failed_stage_preserved(self, tmp_path):
        client, _ = _make_client(
            tmp_path,
            sessions=[
                _session(
                    status=HealthStageStatus.FAILED,
                    stages=(
                        _stage("discovery", "failed", error="boom"),
                    ),
                )
            ],
        )
        response = client.get("/api/v1/health/sessions/hs_test_001/stages")
        assert response.status_code == 200
        (stage,) = response.json()["stages"]
        assert stage["status"] == "failed"
        assert stage["error"] == "boom"


class TestNoPayloadExpansion:
    def test_no_payloads_in_any_response(self, tmp_path):
        client, _ = _make_client(tmp_path, sessions=[_session()])
        bodies = [
            client.get("/api/v1/health/sessions").text,
            client.get("/api/v1/health/sessions/hs_test_001").text,
            client.get("/api/v1/health/sessions/hs_test_001/stages").text,
        ]
        for body in bodies:
            assert "payload_json" not in body
            assert "snapshots" not in body
            assert "findings" not in body


class TestReadOnly:
    def test_no_mutation_routes(self):
        from app.api.routes import router

        health_paths = {
            route.path
            for route in router.routes
            if route.path.startswith("/api/v1/health/")
        }
        assert health_paths == {
            "/api/v1/health/sessions",
            "/api/v1/health/sessions/{session_id}",
            "/api/v1/health/sessions/{session_id}/stages",
        }
        for route in router.routes:
            if route.path in health_paths:
                assert set(route.methods) == {"GET"}

    def test_no_forbidden_imports_in_health_endpoints(self):
        source = (
            Path(__file__).resolve().parent.parent
            / "app"
            / "api"
            / "routes.py"
        ).read_text(encoding="utf-8")
        start = source.index("def get_health_sessions")
        body = source[start:]
        assert "HealthSessionRunner" not in body
        assert "run_discovery" not in body
        assert "analyze_latest_run" not in body
        assert "run_advisory" not in body
        assert "evaluate_candidates" not in body
        tree = ast.parse(body)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported = [node.module or ""]
            else:
                continue
            for name in imported:
                assert "executor" not in name
                assert "confirmation" not in name
                assert "subprocess" not in name

    def test_queries_do_not_create_sessions(self, tmp_path):
        client, store = _make_client(tmp_path)
        client.get("/api/v1/health/sessions")
        client.get("/api/v1/health/sessions/hs_missing")
        client.get("/api/v1/health/sessions/hs_missing/stages")
        assert store.list_sessions() == []


class TestSerialization:
    def test_responses_are_deterministic(self, tmp_path):
        client, _ = _make_client(tmp_path, sessions=[_session()])
        first = client.get("/api/v1/health/sessions/hs_test_001").text
        second = client.get("/api/v1/health/sessions/hs_test_001").text
        assert json.loads(first) == json.loads(second)
