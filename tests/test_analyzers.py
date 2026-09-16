"""Tests for the analyzer package."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from app.analyzers import (
    process_analyzer,
    service_analyzer,
    startup_analyzer,
    storage_analyzer,
    task_analyzer,
)
from app.analyzers.finding import Finding
from app.analyzers.runner import analyze_latest_run, run_analyzers, save_findings
from app.database.sqlite import SnapshotStore


# ── Storage analyzer ────────────────────────────────────────────────────

class TestStorageAnalyzer:
    def test_empty_storage_returns_no_findings(self) -> None:
        assert storage_analyzer.analyze({}) == []
        assert storage_analyzer.analyze({"storage": []}) == []

    def test_below_warning_returns_no_findings(self) -> None:
        snaps = {"storage": [{"mountpoint": "/", "percent_used": 50}]}
        assert storage_analyzer.analyze(snaps) == []

    def test_at_warning_threshold(self) -> None:
        snaps = {"storage": [{"mountpoint": "/", "percent_used": 80, "device": "C:"}]}
        findings = storage_analyzer.analyze(snaps)
        assert len(findings) == 1
        assert findings[0].severity == "warning"
        assert findings[0].analyzer == "storage"

    def test_at_critical_threshold(self) -> None:
        snaps = {"storage": [{"mountpoint": "/", "percent_used": 90, "device": "C:"}]}
        findings = storage_analyzer.analyze(snaps)
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_above_critical_threshold(self) -> None:
        snaps = {"storage": [{"mountpoint": "/", "percent_used": 99.9}]}
        findings = storage_analyzer.analyze(snaps)
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_multiple_partitions(self) -> None:
        snaps = {
            "storage": [
                {"mountpoint": "/", "percent_used": 50},
                {"mountpoint": "/home", "percent_used": 85},
                {"mountpoint": "/var", "percent_used": 95},
            ]
        }
        findings = storage_analyzer.analyze(snaps)
        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert severities == {"warning", "critical"}

    def test_missing_percent_skipped(self) -> None:
        snaps = {"storage": [{"mountpoint": "/"}]}
        assert storage_analyzer.analyze(snaps) == []

    def test_finding_is_frozen_dataclass(self) -> None:
        snaps = {"storage": [{"mountpoint": "/", "percent_used": 90}]}
        findings = storage_analyzer.analyze(snaps)
        assert isinstance(findings[0], Finding)
        with pytest.raises(AttributeError):
            findings[0].severity = "info"  # type: ignore[misc]


# ── Startup analyzer ────────────────────────────────────────────────────

class TestStartupAnalyzer:
    def test_empty_returns_no_findings(self) -> None:
        assert startup_analyzer.analyze({}) == []
        assert startup_analyzer.analyze({"startup": []}) == []

    def test_below_threshold_returns_no_findings(self) -> None:
        snaps = {"startup": [{"Name": f"app{i}"} for i in range(10)]}
        assert startup_analyzer.analyze(snaps) == []

    def test_at_threshold_returns_no_findings(self) -> None:
        snaps = {"startup": [{"Name": f"app{i}"} for i in range(10)]}
        assert startup_analyzer.analyze(snaps) == []

    def test_above_threshold_returns_warning(self) -> None:
        snaps = {"startup": [{"Name": f"app{i}"} for i in range(11)]}
        findings = startup_analyzer.analyze(snaps)
        assert len(findings) == 1
        assert findings[0].severity == "warning"
        assert findings[0].analyzer == "startup"
        assert "11" in findings[0].title

    def test_evidence_includes_entry_list(self) -> None:
        snaps = {"startup": [{"Name": f"app{i}"} for i in range(15)]}
        findings = startup_analyzer.analyze(snaps)
        assert findings[0].evidence["count"] == 15
        assert len(findings[0].evidence["entries"]) == 15


# ── Process analyzer ────────────────────────────────────────────────────

class TestProcessAnalyzer:
    def test_empty_returns_no_findings(self) -> None:
        assert process_analyzer.analyze({}) == []

    def test_low_cpu_low_memory_returns_no_findings(self) -> None:
        snaps = {
            "processes": [
                {"pid": 1, "name": "idle", "cpu_percent": 0.5, "memory_rss_bytes": 1_000_000}
            ],
            "hardware": {"memory_total_bytes": 8_000_000_000},
        }
        assert process_analyzer.analyze(snaps) == []

    def test_high_cpu_returns_warning(self) -> None:
        snaps = {
            "processes": [
                {"pid": 100, "name": "stress", "cpu_percent": 95.0, "memory_rss_bytes": 1_000_000}
            ],
            "hardware": {"memory_total_bytes": 8_000_000_000},
        }
        findings = process_analyzer.analyze(snaps)
        assert len(findings) >= 1
        cpu_findings = [f for f in findings if f.metadata.get("category") == "high_cpu"]
        assert len(cpu_findings) == 1
        assert cpu_findings[0].severity == "warning"
        assert "stress" in cpu_findings[0].title

    def test_high_memory_returns_warning(self) -> None:
        snaps = {
            "processes": [
                {"pid": 200, "name": "leak", "cpu_percent": 5.0, "memory_rss_bytes": 2_000_000_000}
            ],
            "hardware": {"memory_total_bytes": 8_000_000_000},
        }
        findings = process_analyzer.analyze(snaps)
        mem_findings = [f for f in findings if f.metadata.get("category") == "high_memory"]
        assert len(mem_findings) == 1
        assert mem_findings[0].severity == "warning"
        assert "leak" in mem_findings[0].title

    def test_no_hardware_data_skips_memory_check(self) -> None:
        snaps = {
            "processes": [
                {"pid": 200, "name": "leak", "cpu_percent": 5.0, "memory_rss_bytes": 2_000_000_000}
            ],
        }
        findings = process_analyzer.analyze(snaps)
        mem_findings = [f for f in findings if f.metadata.get("category") == "high_memory"]
        assert mem_findings == []

    def test_top_n_caps_findings_per_category(self) -> None:
        processes = [
            {"pid": i, "name": f"proc{i}", "cpu_percent": 99.0, "memory_rss_bytes": 1_000_000}
            for i in range(10)
        ]
        snaps = {"processes": processes, "hardware": {"memory_total_bytes": 8_000_000_000}}
        findings = process_analyzer.analyze(snaps)
        cpu_findings = [f for f in findings if f.metadata.get("category") == "high_cpu"]
        assert len(cpu_findings) == 5


# ── Service analyzer (no findings expected) ─────────────────────────────

class TestServiceAnalyzer:
    def test_returns_empty(self) -> None:
        snaps = {
            "services": [
                {"Name": "WSearch", "State": "Running", "StartMode": "Auto"}
            ]
        }
        assert service_analyzer.analyze(snaps) == []

    def test_empty_snapshots(self) -> None:
        assert service_analyzer.analyze({}) == []


# ── Task analyzer (no findings expected) ────────────────────────────────

class TestTaskAnalyzer:
    def test_returns_empty(self) -> None:
        snaps = {
            "scheduled_tasks": [
                {"TaskName": "\\Microsoft\\Windows\\Defrag", "State": "Ready"}
            ]
        }
        assert task_analyzer.analyze(snaps) == []

    def test_empty_snapshots(self) -> None:
        assert task_analyzer.analyze({}) == []


# ── Runner / orchestrator ───────────────────────────────────────────────

class TestRunner:
    def test_run_analyzers_aggregates_results(self) -> None:
        snaps = {
            "storage": [{"mountpoint": "/", "percent_used": 95}],
            "startup": [{"Name": f"app{i}"} for i in range(15)],
            "processes": [],
            "services": [],
            "scheduled_tasks": [],
        }
        findings, errors = run_analyzers(snaps)
        assert len(findings) >= 2
        assert errors == []
        analyzers_hit = {f.analyzer for f in findings}
        assert "storage" in analyzers_hit
        assert "startup" in analyzers_hit

    def test_analyzer_exception_recorded_as_error(self) -> None:
        import types

        bad = types.ModuleType("bad")
        bad.name = "bad_analyzer"  # type: ignore[attr-defined]
        bad.analyze = lambda snaps: 1 / 0  # type: ignore[attr-defined]

        import app.analyzers.runner as runner_mod

        original = runner_mod.Analyzers
        runner_mod.Analyzers = [bad]  # type: ignore[assignment]
        try:
            _, errors = run_analyzers({})
            assert len(errors) == 1
            assert errors[0]["analyzer"] == "bad_analyzer"
            assert errors[0]["error_type"] == "ZeroDivisionError"
        finally:
            runner_mod.Analyzers = original

    def test_save_findings_persists_to_db(self) -> None:
        findings = [
            Finding(analyzer="test", severity="warning", title="T", message="M"),
            Finding(analyzer="test", severity="critical", title="T2", message="M2"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SnapshotStore(path=db_path)
            run_id = store.start_run()
            store.complete_run(run_id, "completed")

            with store._connect() as conn:
                save_findings(conn, run_id, findings, [])

            loaded = store.load_findings(run_id)
            assert len(loaded) == 2
            assert loaded[0]["severity"] == "warning"
            assert loaded[1]["severity"] == "critical"

    def test_analyze_latest_run_no_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SnapshotStore(path=Path(tmpdir) / "test.db")
            result = analyze_latest_run(store)
            assert result["run_id"] is None
            assert result["findings_count"] == 0

    def test_analyze_latest_run_with_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SnapshotStore(path=Path(tmpdir) / "test.db")
            run_id = store.start_run()
            store.save("storage", [{"mountpoint": "/", "percent_used": 92}], run_id=run_id)
            store.complete_run(run_id, "completed")

            result = analyze_latest_run(store)
            assert result["run_id"] == run_id
            assert result["findings_count"] >= 1
            assert result["errors_count"] == 0

            stored = store.load_findings(run_id)
            assert len(stored) >= 1
            assert stored[0]["severity"] == "critical"
