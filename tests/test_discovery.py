"""Tests for the discovery orchestrator."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from app.collectors.result import CollectorResult
from app.database.sqlite import SnapshotStore
from app.discovery import _run_collector, run


class TestRunCollector:
    def test_returns_collector_result(self) -> None:
        def good() -> CollectorResult:
            return CollectorResult(payload={"x": 1}, status="ok")

        cr = _run_collector("test", good)
        assert isinstance(cr, CollectorResult)
        assert cr.status == "ok"
        assert cr.payload == {"x": 1}

    def test_rejects_non_collector_result(self) -> None:
        def bad() -> dict[str, int]:
            return {"x": 1}

        cr = _run_collector("test", bad)
        assert cr.status == "failed"
        assert "TypeError" in cr.error_message  # type: ignore[operator]
        assert "expected CollectorResult" in cr.error_message  # type: ignore[operator]

    def test_rejects_none_return(self) -> None:
        def none_return() -> None:
            return None

        cr = _run_collector("test", none_return)
        assert cr.status == "failed"
        assert "TypeError" in cr.error_message  # type: ignore[operator]

    def test_catches_exception(self) -> None:
        def explodes() -> CollectorResult:
            raise RuntimeError("boom")

        cr = _run_collector("test", explodes)
        assert cr.status == "failed"
        assert "RuntimeError: boom" in cr.error_message  # type: ignore[operator]
        assert cr.payload is None

    def test_wraps_empty_result(self) -> None:
        def empty() -> CollectorResult:
            return CollectorResult(payload=[], status="empty")

        cr = _run_collector("test", empty)
        assert cr.status == "empty"
        assert cr.payload == []


class TestRunDiscovery:
    def test_full_run_with_mocked_collectors(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SnapshotStore(path=db_path)

            mock_collectors = {
                "hardware": lambda: CollectorResult(payload={"ram": 16}, status="ok"),
                "storage": lambda: CollectorResult(payload=[], status="empty"),
                "battery": lambda: CollectorResult(
                    payload=None, status="failed", error_message="test error"
                ),
            }

            with patch("app.discovery.COLLECTORS", mock_collectors):
                results, summary = run(store=store)

            assert results["hardware"] == {"ram": 16}
            assert results["storage"] == []
            assert results["battery"] is None

            assert summary["overall_status"] == "completed_with_errors"
            assert summary["collector_count"] == 3
            assert summary["successful_count"] == 1
            assert summary["empty_count"] == 1
            assert summary["failed_count"] == 1

            assert summary["collectors"]["hardware"]["status"] == "ok"
            assert summary["collectors"]["storage"]["status"] == "empty"
            assert summary["collectors"]["battery"]["status"] == "failed"
            assert summary["collectors"]["battery"]["error_message"] == "test error"

    def test_run_id_association(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SnapshotStore(path=db_path)

            mock_collectors = {
                "hardware": lambda: CollectorResult(payload={"x": 1}, status="ok"),
            }

            with patch("app.discovery.COLLECTORS", mock_collectors):
                results, summary = run(store=store)

            run_id = summary["run_id"]
            assert run_id is not None

            import sqlite3

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("SELECT run_id, category FROM snapshots")
            rows = c.fetchall()
            conn.close()

            assert len(rows) == 1
            assert rows[0][0] == run_id
            assert rows[0][1] == "hardware"
