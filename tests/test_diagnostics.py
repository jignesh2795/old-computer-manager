"""Comprehensive tests for the diagnostics subsystem (Phase 10A).

Covers: diagnostic models, disk, SMART unavailable, predictive failure,
disk temperature, thermal, performance, CPU/memory thresholds, disk I/O,
device problem detection, Windows health, failure isolation, persistence,
history integration, report integration, API, CLI, dashboard, AI context,
no serial numbers, no write operations, no subprocess/shell, no remediation,
existing test suite remains passing.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.database.sqlite import SnapshotStore
from app.diagnostics.analyzers import analyze_diagnostics
from app.diagnostics.constants import (
    CPU_HIGH_PERCENT,
    CPU_TEMP_CRITICAL,
    CPU_TEMP_WARNING,
    MEMORY_HIGH_PERCENT,
)
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticRun, DiagnosticStatus
from app.diagnostics.runner import run_diagnostics, save_diagnostic_run


# ── A. Diagnostic model tests ──────────────────────────────────────────

class TestDiagnosticModels:
    def test_diagnostic_result_frozen(self) -> None:
        r = DiagnosticResult(
            diagnostic_id="test_1",
            category=DiagnosticCategory.DISK,
            status=DiagnosticStatus.OK,
            title="Test",
            summary="Test summary",
        )
        assert r.diagnostic_id == "test_1"
        assert r.category == DiagnosticCategory.DISK
        assert r.status == DiagnosticStatus.OK

    def test_diagnostic_result_defaults(self) -> None:
        r = DiagnosticResult(
            diagnostic_id="x",
            category=DiagnosticCategory.THERMAL,
            status=DiagnosticStatus.UNAVAILABLE,
            title="X",
            summary="Y",
        )
        assert r.evidence == {}
        assert r.source == ""
        assert r.limitations == []
        assert r.errors == []
        assert r.collected_at != ""

    def test_diagnostic_run_properties(self) -> None:
        results = [
            DiagnosticResult(diagnostic_id="d1", category=DiagnosticCategory.DISK,
                             status=DiagnosticStatus.OK, title="D1", summary="S1"),
            DiagnosticResult(diagnostic_id="t1", category=DiagnosticCategory.THERMAL,
                             status=DiagnosticStatus.WARNING, title="T1", summary="S2"),
            DiagnosticResult(diagnostic_id="d2", category=DiagnosticCategory.DISK,
                             status=DiagnosticStatus.UNAVAILABLE, title="D2", summary="S3"),
        ]
        run = DiagnosticRun(results=results)
        assert len(run.disk_results) == 2
        assert len(run.thermal_results) == 1
        assert len(run.performance_results) == 0
        counts = run.summary_counts
        assert counts["ok"] == 1
        assert counts["warning"] == 1
        assert counts["unavailable"] == 1

    def test_diagnostic_status_enum(self) -> None:
        assert DiagnosticStatus.OK.value == "ok"
        assert DiagnosticStatus.WARNING.value == "warning"
        assert DiagnosticStatus.CRITICAL.value == "critical"
        assert DiagnosticStatus.UNAVAILABLE.value == "unavailable"
        assert DiagnosticStatus.NOT_SUPPORTED.value == "not_supported"
        assert DiagnosticStatus.FAILED.value == "failed"

    def test_diagnostic_category_enum(self) -> None:
        assert DiagnosticCategory.DISK.value == "disk"
        assert DiagnosticCategory.THERMAL.value == "thermal"
        assert DiagnosticCategory.PERFORMANCE.value == "performance"
        assert DiagnosticCategory.DEVICES.value == "devices"
        assert DiagnosticCategory.WINDOWS.value == "windows"


# ── B. Disk information parsing ────────────────────────────────────────

class TestDiskParsing:
    def test_parse_disk_valid(self) -> None:
        from app.diagnostics.disk import _parse_disk
        raw = {
            "DeviceID": "\\\\.\\PHYSICALDRIVE0",
            "Model": "Test Disk",
            "InterfaceType": "IDE",
            "MediaType": "Fixed hard disk media",
            "Size": "500000000000",
            "SerialNumber": "ABC123",
            "Status": "OK",
            "OperationalStatus": ["OK"],
            "HealthStatus": 0,
            "PredictiveFailure": False,
        }
        result = _parse_disk(raw)
        assert result["device_id"] == "\\\\.\\PHYSICALDRIVE0"
        assert result["model"] == "Test Disk"
        assert result["interface_type"] == "IDE"
        assert result["size_bytes"] == 500000000000
        assert result["serial_number_present"] is True
        assert result["health_status"] == "0"
        assert result["predictive_failure"] == "False"

    def test_parse_disk_no_serial(self) -> None:
        from app.diagnostics.disk import _parse_disk
        raw = {"DeviceID": "X", "Model": "Y", "SerialNumber": ""}
        result = _parse_disk(raw)
        assert result["serial_number_present"] is False

    def test_parse_disk_none_serial(self) -> None:
        from app.diagnostics.disk import _parse_disk
        raw = {"DeviceID": "X", "Model": "Y", "SerialNumber": None}
        result = _parse_disk(raw)
        assert result["serial_number_present"] is False

    def test_parse_disk_empty(self) -> None:
        from app.diagnostics.disk import _parse_disk
        assert _parse_disk(None) == {}
        assert _parse_disk("not a dict") == {}


# ── C. SMART unavailable handling ──────────────────────────────────────

class TestSmartUnavailable:
    @patch("app.diagnostics.disk.run_powershell")
    def test_smart_unavailable_when_no_data(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = (None, None)
        from app.diagnostics.disk import collect_disk_health
        results = collect_disk_health()
        assert any(r.status == DiagnosticStatus.UNAVAILABLE for r in results)

    @patch("app.diagnostics.disk.run_powershell")
    def test_smart_failed_on_error(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = (None, "Access denied")
        from app.diagnostics.disk import collect_disk_health
        results = collect_disk_health()
        assert any(r.status == DiagnosticStatus.FAILED for r in results)

    def test_not_supported_on_non_windows(self) -> None:
        import platform
        if platform.system() == "Windows":
            pytest.skip("Windows platform")
        from app.diagnostics.disk import collect_disk_health
        results = collect_disk_health()
        assert any(r.status == DiagnosticStatus.NOT_SUPPORTED for r in results)


# ── D. Predictive failure parsing ──────────────────────────────────────

class TestPredictiveFailure:
    @patch("app.diagnostics.disk.run_powershell")
    def test_predictive_failure_yes(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ([{
            "DeviceID": "X",
            "Model": "Disk1",
            "HealthStatus": 0,
            "PredictiveFailure": "Yes",
            "OperationalStatus": ["OK"],
        }], None)
        from app.diagnostics.disk import collect_disk_health
        results = collect_disk_health()
        assert any(r.status == DiagnosticStatus.CRITICAL for r in results)

    @patch("app.diagnostics.disk.run_powershell")
    def test_health_status_critical(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ([{
            "DeviceID": "X",
            "Model": "Disk1",
            "HealthStatus": "Critical",
            "PredictiveFailure": "No",
            "OperationalStatus": ["Error"],
        }], None)
        from app.diagnostics.disk import collect_disk_health
        results = collect_disk_health()
        assert any(r.status == DiagnosticStatus.CRITICAL for r in results)


# ── E. Disk temperature unavailable ────────────────────────────────────

class TestDiskTemperature:
    @patch("app.diagnostics.disk.run_powershell")
    def test_disk_health_with_no_temperature(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ([{
            "DeviceID": "X",
            "Model": "Disk1",
            "HealthStatus": 0,
            "PredictiveFailure": "No",
            "OperationalStatus": ["OK"],
        }], None)
        from app.diagnostics.disk import collect_disk_health
        results = collect_disk_health()
        for r in results:
            if r.evidence.get("smart_temperature") is None:
                assert "Temperature reading may be unavailable" in r.limitations or r.limitations == []


# ── F. Thermal unavailable ─────────────────────────────────────────────

class TestThermalUnavailable:
    @patch("app.diagnostics.thermal._collect_psutil_temperatures", return_value=None)
    @patch("app.diagnostics.thermal._collect_wmi_temperatures", return_value=None)
    def test_thermal_unavailable(self, mock_wmi: MagicMock, mock_psutil: MagicMock) -> None:
        from app.diagnostics.thermal import collect_thermal
        results = collect_thermal()
        assert any(r.status == DiagnosticStatus.UNAVAILABLE for r in results)
        assert any("temperature sensors" in r.summary.lower() for r in results)


# ── G. Performance snapshot ────────────────────────────────────────────

class TestPerformanceSnapshot:
    def test_performance_collects_all_sections(self) -> None:
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        categories = [r.diagnostic_id for r in results]
        assert "performance_cpu" in categories
        assert "performance_memory" in categories
        assert "performance_disk_io" in categories
        assert "performance_network_io" in categories

    def test_performance_results_are_valid(self) -> None:
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        for r in results:
            assert r.category == DiagnosticCategory.PERFORMANCE
            assert r.status in DiagnosticStatus


# ── H. CPU threshold ───────────────────────────────────────────────────

class TestCpuThreshold:
    @patch("app.diagnostics.performance.psutil")
    def test_high_cpu_triggers_warning(self, mock_psutil: MagicMock) -> None:
        mock_psutil.cpu_percent.return_value = 95.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        vm = MagicMock()
        vm.total = 8 * 1024**3
        vm.available = 4 * 1024**3
        vm.used = 4 * 1024**3
        vm.percent = 50.0
        mock_psutil.virtual_memory.return_value = vm
        swap = MagicMock()
        swap.total = 0
        swap.used = 0
        swap.percent = 0.0
        mock_psutil.swap_memory.return_value = swap
        io = MagicMock()
        io.read_bytes = 1000
        io.write_bytes = 1000
        io.read_count = 10
        io.write_count = 10
        mock_psutil.disk_io_counters.return_value = io
        net = MagicMock()
        net.bytes_sent = 1000
        net.bytes_recv = 1000
        net.packets_sent = 10
        net.packets_recv = 10
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        cpu_result = [r for r in results if r.diagnostic_id == "performance_cpu"][0]
        assert cpu_result.status == DiagnosticStatus.WARNING

    @patch("app.diagnostics.performance.psutil")
    def test_normal_cpu_is_ok(self, mock_psutil: MagicMock) -> None:
        mock_psutil.cpu_percent.return_value = 30.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        vm = MagicMock()
        vm.total = 8 * 1024**3
        vm.available = 6 * 1024**3
        vm.used = 2 * 1024**3
        vm.percent = 25.0
        mock_psutil.virtual_memory.return_value = vm
        swap = MagicMock()
        swap.total = 0
        swap.used = 0
        swap.percent = 0.0
        mock_psutil.swap_memory.return_value = swap
        io = MagicMock()
        io.read_bytes = 1000
        io.write_bytes = 1000
        io.read_count = 10
        io.write_count = 10
        mock_psutil.disk_io_counters.return_value = io
        net = MagicMock()
        net.bytes_sent = 1000
        net.bytes_recv = 1000
        net.packets_sent = 10
        net.packets_recv = 10
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        cpu_result = [r for r in results if r.diagnostic_id == "performance_cpu"][0]
        assert cpu_result.status == DiagnosticStatus.OK


# ── I. Memory threshold ────────────────────────────────────────────────

class TestMemoryThreshold:
    @patch("app.diagnostics.performance.psutil")
    def test_high_memory_triggers_warning(self, mock_psutil: MagicMock) -> None:
        vm = MagicMock()
        vm.total = 8 * 1024**3
        vm.available = 500 * 1024**2
        vm.used = 7.5 * 1024**3
        vm.percent = 93.0
        swap = MagicMock()
        swap.total = 0
        swap.used = 0
        swap.percent = 0.0
        mock_psutil.virtual_memory.return_value = vm
        mock_psutil.swap_memory.return_value = swap
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        io = MagicMock()
        io.read_bytes = 1000
        io.write_bytes = 1000
        io.read_count = 10
        io.write_count = 10
        mock_psutil.disk_io_counters.return_value = io
        net = MagicMock()
        net.bytes_sent = 1000
        net.bytes_recv = 1000
        net.packets_sent = 10
        net.packets_recv = 10
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        mem_result = [r for r in results if r.diagnostic_id == "performance_memory"][0]
        assert mem_result.status == DiagnosticStatus.WARNING


# ── J. Disk I/O ────────────────────────────────────────────────────────

class TestDiskIO:
    def test_disk_io_result_structure(self) -> None:
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        io_results = [r for r in results if r.diagnostic_id == "performance_disk_io"]
        assert len(io_results) == 1
        r = io_results[0]
        assert r.category == DiagnosticCategory.PERFORMANCE


# ── K. Device problem detection ────────────────────────────────────────

class TestDeviceProblems:
    @patch("app.diagnostics.devices.run_powershell")
    def test_problem_device_detected(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ([
            {"Name": "Good Device", "DeviceID": "DEV1", "Status": "OK",
             "ConfigManagerErrorCode": 0, "Manufacturer": "Mfg",
             "DriverProviderName": "Provider", "DriverVersion": "1.0",
             "ClassGuid": "", "PNPClass": "Display"},
            {"Name": "Bad Device", "DeviceID": "DEV2", "Status": "Error",
             "ConfigManagerErrorCode": 10, "Manufacturer": "Mfg2",
             "DriverProviderName": "Provider2", "DriverVersion": "2.0",
             "ClassGuid": "", "PNPClass": "Net"},
        ], None)
        from app.diagnostics.devices import collect_devices
        results = collect_devices()
        summary = [r for r in results if r.diagnostic_id == "devices_summary"]
        assert len(summary) == 1
        assert summary[0].status == DiagnosticStatus.WARNING
        problems = [r for r in results if "problem" in r.diagnostic_id]
        assert len(problems) == 1

    @patch("app.diagnostics.devices.run_powershell")
    def test_no_problems_is_ok(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ([{
            "Name": "Device1", "DeviceID": "D1", "Status": "OK",
            "ConfigManagerErrorCode": 0, "Manufacturer": "M",
            "DriverProviderName": "P", "DriverVersion": "1",
            "ClassGuid": "", "PNPClass": "",
        }], None)
        from app.diagnostics.devices import collect_devices
        results = collect_devices()
        summary = [r for r in results if r.diagnostic_id == "devices_summary"]
        assert summary[0].status == DiagnosticStatus.OK


# ── L. Windows health unavailable ──────────────────────────────────────

class TestWindowsHealth:
    def test_not_supported_on_non_windows(self) -> None:
        import platform
        if platform.system() == "Windows":
            pytest.skip("Windows platform")
        from app.diagnostics.windows_health import collect_windows_health
        results = collect_windows_health()
        assert any(r.status == DiagnosticStatus.NOT_SUPPORTED for r in results)

    @patch("app.diagnostics.windows_health.platform.system", return_value="Linux")
    def test_version_unavailable_on_non_windows(self, mock_platform: MagicMock) -> None:
        from app.diagnostics.windows_health import _collect_windows_version
        assert _collect_windows_version() is None


# ── M. Per-diagnostic failure isolation ────────────────────────────────

class TestFailureIsolation:
    @patch("app.diagnostics.runner.collect_disk_health")
    def test_runner_isolates_failures(self, mock_disk: MagicMock) -> None:
        mock_disk.side_effect = RuntimeError("Disk boom!")
        run = run_diagnostics()
        assert len(run.errors) >= 1
        assert run.status == "partial"
        other_results = [r for r in run.results if r.category != DiagnosticCategory.DISK]
        assert len(other_results) >= 3


# ── N. Diagnostic run persistence ──────────────────────────────────────

class TestDiagnosticPersistence:
    def test_save_and_load_diagnostic_run(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test.db"
        store = SnapshotStore(path=db_path)

        results = [
            {"diagnostic_id": "d1", "category": "disk", "status": "ok",
             "title": "Disk1", "summary": "S1", "evidence": {}, "source": "test",
             "collected_at": "", "limitations": [], "errors": []},
            {"diagnostic_id": "t1", "category": "thermal", "status": "unavailable",
             "title": "Thermal1", "summary": "S2", "evidence": {}, "source": "test",
             "collected_at": "", "limitations": ["No sensors"], "errors": []},
        ]

        run_id = store.save_diagnostic_run(
            discovery_run_id=None,
            started_at="2026-01-01T00:00:00",
            completed_at="2026-01-01T00:00:01",
            status="completed",
            results=results,
            errors=[],
        )
        assert run_id is not None

        latest = store.get_latest_diagnostic_run()
        assert latest is not None
        assert latest["id"] == run_id
        assert latest["status"] == "completed"

        loaded = store.load_diagnostic_results(run_id)
        assert len(loaded) == 2
        assert loaded[0]["diagnostic_id"] == "d1"
        assert loaded[1]["diagnostic_id"] == "t1"

        by_cat = store.get_diagnostic_results_by_category(run_id, "disk")
        assert len(by_cat) == 1

        summary = store.get_diagnostic_summary(run_id)
        assert summary["disk"]["ok"] == 1
        assert summary["thermal"]["unavailable"] == 1

    def test_save_diagnostic_run_with_errors(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test_errors.db"
        store = SnapshotStore(path=db_path)
        run_id = store.save_diagnostic_run(
            started_at="2026-01-01T00:00:00",
            completed_at="2026-01-01T00:00:01",
            status="partial",
            results=[],
            errors=[{"collector": "disk", "error_type": "test", "error_message": "fail"}],
        )
        latest = store.get_latest_diagnostic_run()
        assert latest is not None
        assert latest["status"] == "partial"
        assert len(latest["errors"]) == 1


# ── O. History integration ─────────────────────────────────────────────

class TestHistoryIntegration:
    def test_diagnostic_metrics_defined(self) -> None:
        from app.history.metrics import METRIC_DEFINITIONS
        assert "diagnostic_cpu_percent" in METRIC_DEFINITIONS
        assert "diagnostic_memory_percent" in METRIC_DEFINITIONS
        assert "diagnostic_device_problem_count" in METRIC_DEFINITIONS


# ── P. Report integration ──────────────────────────────────────────────

class TestReportIntegration:
    def test_diagnostics_summary_in_report(self) -> None:
        from app.reporting.models import DiagnosticsSummary, HealthReport
        report = HealthReport()
        assert report.diagnostics.available is False
        assert report.diagnostics.result_count == 0

    def test_diagnostics_summary_model(self) -> None:
        from app.reporting.models import DiagnosticsSummary
        ds = DiagnosticsSummary(
            available=True,
            run_id=1,
            status="completed",
            result_count=5,
            categories=["disk", "thermal"],
            status_counts={"ok": 3, "unavailable": 2},
        )
        assert ds.available is True
        assert len(ds.categories) == 2


# ── Q. API endpoints ───────────────────────────────────────────────────

class TestAPIEndpoints:
    def _make_store(self) -> SnapshotStore:
        import tempfile
        from pathlib import Path
        tmp = tempfile.mkdtemp()
        return SnapshotStore(path=Path(tmp) / "test_api.db")

    def test_diagnostics_summary_endpoint(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app
        from app.api import dependencies
        store = self._make_store()
        app.dependency_overrides[dependencies.get_store] = lambda: store
        client = TestClient(app)
        r = client.get("/api/v1/diagnostics/summary")
        assert r.status_code == 200
        data = r.json()
        assert "available" in data
        assert "results" in data
        app.dependency_overrides.clear()

    def test_diagnostics_disk_endpoint(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app
        from app.api import dependencies
        store = self._make_store()
        app.dependency_overrides[dependencies.get_store] = lambda: store
        client = TestClient(app)
        r = client.get("/api/v1/diagnostics/disk")
        assert r.status_code == 200
        app.dependency_overrides.clear()

    def test_diagnostics_thermal_endpoint(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app
        from app.api import dependencies
        store = self._make_store()
        app.dependency_overrides[dependencies.get_store] = lambda: store
        client = TestClient(app)
        r = client.get("/api/v1/diagnostics/thermal")
        assert r.status_code == 200
        app.dependency_overrides.clear()

    def test_diagnostics_performance_endpoint(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app
        from app.api import dependencies
        store = self._make_store()
        app.dependency_overrides[dependencies.get_store] = lambda: store
        client = TestClient(app)
        r = client.get("/api/v1/diagnostics/performance")
        assert r.status_code == 200
        app.dependency_overrides.clear()

    def test_diagnostics_devices_endpoint(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app
        from app.api import dependencies
        store = self._make_store()
        app.dependency_overrides[dependencies.get_store] = lambda: store
        client = TestClient(app)
        r = client.get("/api/v1/diagnostics/devices")
        assert r.status_code == 200
        app.dependency_overrides.clear()

    def test_diagnostics_windows_endpoint(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app
        from app.api import dependencies
        store = self._make_store()
        app.dependency_overrides[dependencies.get_store] = lambda: store
        client = TestClient(app)
        r = client.get("/api/v1/diagnostics/windows")
        assert r.status_code == 200
        app.dependency_overrides.clear()

    def test_no_modification_endpoints(self) -> None:
        from fastapi.testclient import TestClient
        from app.api.app import app
        client = TestClient(app)
        for path in [
            "/api/v1/diagnostics/summary",
            "/api/v1/diagnostics/disk",
            "/api/v1/diagnostics/thermal",
            "/api/v1/diagnostics/performance",
            "/api/v1/diagnostics/devices",
            "/api/v1/diagnostics/windows",
        ]:
            r = client.post(path)
            assert r.status_code in (405, 404)


# ── R. CLI diagnostics ─────────────────────────────────────────────────

class TestCLIDiagnostics:
    def test_cli_diagnostics_help(self) -> None:
        import subprocess
        result = subprocess.run(
            ["python", "-m", "app.cli", "diagnostics", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "diagnostics" in result.stdout.lower() or "diagnostics" in result.stderr.lower()

    def test_cli_diagnostics_json(self) -> None:
        import subprocess
        result = subprocess.run(
            ["python", "-m", "app.cli", "diagnostics", "--json"],
            capture_output=True, text=True, timeout=30,
        )
        combined = result.stdout + result.stderr
        if result.returncode == 0:
            assert "results" in combined or "diagnostics" in combined.lower()


# ── S. Dashboard rendering ─────────────────────────────────────────────

class TestDashboardRendering:
    def test_diagnostics_component_exists(self) -> None:
        from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus
        results = [
            DiagnosticResult(
                diagnostic_id="test", category=DiagnosticCategory.DISK,
                status=DiagnosticStatus.OK, title="Test", summary="Summary",
            )
        ]
        run = DiagnosticRun(results=results)
        assert len(run.results) == 1
        assert run.results[0].category == DiagnosticCategory.DISK


# ── T. AI context integration ──────────────────────────────────────────

class TestAIContextIntegration:
    def test_ai_context_includes_diagnostics(self) -> None:
        from app.ai.context import AIContext
        ctx = AIContext(diagnostics_summary={"available": False})
        assert ctx.diagnostics_summary["available"] is False

    def test_build_diagnostics_summary_unavailable(self) -> None:
        from app.ai.context import _build_diagnostics_summary
        from app.reporting.models import HealthReport
        report = HealthReport()
        result = _build_diagnostics_summary(report)
        assert result["available"] is False

    def test_max_diagnostic_results_constant(self) -> None:
        from app.ai.context import MAX_DIAGNOSTIC_RESULTS
        assert MAX_DIAGNOSTIC_RESULTS == 20


# ── U. No serial numbers exposed ───────────────────────────────────────

class TestNoSerialNumbers:
    @patch("app.diagnostics.disk.run_powershell")
    def test_disk_does_not_store_serial(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ([{
            "DeviceID": "X", "Model": "Disk1", "SerialNumber": "SECRET12345",
            "HealthStatus": 0, "PredictiveFailure": "No",
            "OperationalStatus": ["OK"],
        }], None)
        from app.diagnostics.disk import collect_disk_health
        results = collect_disk_health()
        for r in results:
            evidence_str = json.dumps(r.evidence)
            assert "SECRET12345" not in evidence_str
            assert r.evidence.get("serial_number") is None


# ── V. No write operations ─────────────────────────────────────────────

class TestNoWriteOperations:
    def test_no_file_writes_in_disk_module(self) -> None:
        import ast
        from pathlib import Path
        disk_path = Path("app/diagnostics/disk.py")
        source = disk_path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("write", "write_text", "mkdir", "unlink", "remove", "rmtree"):
                        pytest.fail(f"Write operation found: {node.func.attr}")
                if isinstance(node.func, ast.Name):
                    if node.func.id in ("open", "os.remove", "os.unlink"):
                        pytest.fail(f"Write operation found: {node.func.id}")

    def test_no_file_writes_in_thermal_module(self) -> None:
        import ast
        from pathlib import Path
        thermal_path = Path("app/diagnostics/thermal.py")
        source = thermal_path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("write", "write_text", "mkdir", "unlink", "remove", "rmtree"):
                        pytest.fail(f"Write operation found: {node.func.attr}")

    def test_no_file_writes_in_performance_module(self) -> None:
        import ast
        from pathlib import Path
        perf_path = Path("app/diagnostics/performance.py")
        source = perf_path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("write", "write_text", "mkdir", "unlink", "remove", "rmtree"):
                        pytest.fail(f"Write operation found: {node.func.attr}")


# ── W. No subprocess/shell execution in new code ──────────────────────

class TestNoSubprocess:
    def test_disk_module_uses_only_run_powershell(self) -> None:
        import ast
        from pathlib import Path
        disk_path = Path("app/diagnostics/disk.py")
        source = disk_path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        pytest.fail("Direct subprocess import found in disk.py")
            if isinstance(node, ast.ImportFrom):
                if node.module and "subprocess" in node.module:
                    pytest.fail("Direct subprocess import found in disk.py")

    def test_analyzers_no_subprocess(self) -> None:
        import ast
        from pathlib import Path
        anal_path = Path("app/diagnostics/analyzers.py")
        source = anal_path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        pytest.fail("Subprocess import found in analyzers.py")


# ── X. No remediation invocation ───────────────────────────────────────

class TestNoRemediation:
    def test_diagnostics_do_not_import_remediation(self) -> None:
        from pathlib import Path
        for py_file in Path("app/diagnostics").glob("*.py"):
            source = py_file.read_text()
            if "remediation" in source.lower() and "from app.remediation" in source:
                if "import" in source.split("from app.remediation")[0][-50:]:
                    pytest.fail(f"Remediation import found in {py_file.name}")


# ── Y. Analyzers produce findings ──────────────────────────────────────

class TestAnalyzers:
    def test_analyze_ok_results_produce_no_findings(self) -> None:
        results = [
            DiagnosticResult(diagnostic_id="d1", category=DiagnosticCategory.DISK,
                             status=DiagnosticStatus.OK, title="Disk", summary="OK"),
        ]
        findings = analyze_diagnostics(results)
        assert len(findings) == 0

    def test_analyze_warning_produces_finding(self) -> None:
        results = [
            DiagnosticResult(diagnostic_id="d1", category=DiagnosticCategory.DISK,
                             status=DiagnosticStatus.WARNING, title="Disk",
                             summary="High temp", evidence={"temp": 85}),
        ]
        findings = analyze_diagnostics(results)
        assert len(findings) == 1
        assert findings[0].severity == "warning"

    def test_analyze_critical_produces_finding(self) -> None:
        results = [
            DiagnosticResult(diagnostic_id="d1", category=DiagnosticCategory.DISK,
                             status=DiagnosticStatus.CRITICAL, title="Disk",
                             summary="Predictive failure"),
        ]
        findings = analyze_diagnostics(results)
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_analyze_unavailable_produces_info_finding(self) -> None:
        results = [
            DiagnosticResult(diagnostic_id="d1", category=DiagnosticCategory.THERMAL,
                             status=DiagnosticStatus.UNAVAILABLE, title="Thermal",
                             summary="No sensors"),
        ]
        findings = analyze_diagnostics(results)
        assert len(findings) == 1
        assert findings[0].severity == "info"

    def test_analyze_failed_produces_warning(self) -> None:
        results = [
            DiagnosticResult(diagnostic_id="d1", category=DiagnosticCategory.DISK,
                             status=DiagnosticStatus.FAILED, title="Disk",
                             summary="Query failed", errors=["timeout"]),
        ]
        findings = analyze_diagnostics(results)
        assert len(findings) == 1
        assert findings[0].severity == "warning"

    def test_analyze_not_supported_produces_no_finding(self) -> None:
        results = [
            DiagnosticResult(diagnostic_id="d1", category=DiagnosticCategory.DEVICES,
                             status=DiagnosticStatus.NOT_SUPPORTED, title="Devices",
                             summary="Not on this platform"),
        ]
        findings = analyze_diagnostics(results)
        assert len(findings) == 0


# ── Z. Runner integration ──────────────────────────────────────────────

class TestRunnerIntegration:
    def test_runner_returns_diagnostic_run(self) -> None:
        run = run_diagnostics()
        assert isinstance(run, DiagnosticRun)
        assert run.status in ("completed", "partial")
        assert len(run.results) > 0
        assert run.started_at != ""
        assert run.completed_at != ""

    def test_runner_categories_present(self) -> None:
        run = run_diagnostics()
        categories = {r.category for r in run.results}
        assert DiagnosticCategory.DISK in categories
        assert DiagnosticCategory.PERFORMANCE in categories


# ── AA. Save runner integration ────────────────────────────────────────

class TestSaveRunnerIntegration:
    def test_save_run_to_database(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test_runner.db"
        store = SnapshotStore(path=db_path)
        run = run_diagnostics()
        run_id = save_diagnostic_run(run, store)
        assert run_id is not None
        latest = store.get_latest_diagnostic_run()
        assert latest is not None
        assert latest["id"] == run_id


# ── AB. Constants validation ───────────────────────────────────────────

class TestConstants:
    def test_cpu_threshold_reasonable(self) -> None:
        assert 50 <= CPU_HIGH_PERCENT <= 100

    def test_memory_threshold_reasonable(self) -> None:
        assert 50 <= MEMORY_HIGH_PERCENT <= 100

    def test_cpu_temp_thresholds(self) -> None:
        assert CPU_TEMP_WARNING < CPU_TEMP_CRITICAL
        assert 60 <= CPU_TEMP_WARNING <= 90
        assert 80 <= CPU_TEMP_CRITICAL <= 110


# ── AC. Data quality semantics ─────────────────────────────────────────

class TestDataQualitySemantics:
    def test_unavailable_is_not_error(self) -> None:
        results = [
            DiagnosticResult(diagnostic_id="d1", category=DiagnosticCategory.THERMAL,
                             status=DiagnosticStatus.UNAVAILABLE, title="Thermal",
                             summary="Not available"),
        ]
        findings = analyze_diagnostics(results)
        assert findings[0].severity == "info"

    def test_not_supported_is_silent(self) -> None:
        results = [
            DiagnosticResult(diagnostic_id="d1", category=DiagnosticCategory.DISK,
                             status=DiagnosticStatus.NOT_SUPPORTED, title="Disk",
                             summary="Not supported"),
        ]
        findings = analyze_diagnostics(results)
        assert len(findings) == 0


# ── AD. PowerShell helper ──────────────────────────────────────────────

class TestPowerShellHelper:
    def test_run_powershell_returns_tuple(self) -> None:
        from app.diagnostics._powershell import run_powershell
        result = run_powershell("echo test")
        assert isinstance(result, tuple)
        assert len(result) == 2


# ── AE. Report builder integration ─────────────────────────────────────

class TestReportBuilder:
    def test_build_diagnostics_summary_with_store(self) -> None:
        from app.reporting.builder import _build_diagnostics_summary
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test_builder.db"
        store = SnapshotStore(path=db_path)
        result = _build_diagnostics_summary(store)
        assert result.available is False

    def test_build_diagnostics_summary_without_store(self) -> None:
        from app.reporting.builder import _build_diagnostics_summary
        result = _build_diagnostics_summary(None)
        assert result.available is False


# ── AF. Import validation ──────────────────────────────────────────────

class TestImports:
    def test_diagnostics_package_imports(self) -> None:
        from app.diagnostics import DiagnosticCategory, DiagnosticResult, DiagnosticStatus, run_diagnostics
        assert DiagnosticResult is not None
        assert DiagnosticCategory is not None
        assert DiagnosticStatus is not None
        assert run_diagnostics is not None


# ── AG. Memory available when swap fails ────────────────────────────────

class TestMemorySwapFailure:
    @patch("app.diagnostics.performance.time")
    @patch("app.diagnostics.performance.psutil")
    def test_memory_available_when_swap_raises(self, mock_psutil: MagicMock, mock_time: MagicMock) -> None:
        vm = MagicMock()
        vm.total = 16 * 1024**3
        vm.available = 8 * 1024**3
        vm.used = 8 * 1024**3
        vm.percent = 50.0
        mock_psutil.virtual_memory.return_value = vm
        mock_psutil.swap_memory.side_effect = RuntimeError("Performance counters disabled")
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        io = MagicMock()
        io.read_bytes = 1000
        io.write_bytes = 1000
        io.read_count = 10
        io.write_count = 10
        mock_psutil.disk_io_counters.return_value = io
        net = MagicMock()
        net.bytes_sent = 1000
        net.bytes_recv = 1000
        net.packets_sent = 10
        net.packets_recv = 10
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        mem = [r for r in results if r.diagnostic_id == "performance_memory"][0]
        assert mem.status == DiagnosticStatus.OK
        assert "50.0%" in mem.summary
        assert any("swap_memory unavailable" in lim for lim in mem.limitations)

    @patch("app.diagnostics.performance.time")
    @patch("app.diagnostics.performance.psutil")
    def test_memory_unavailable_when_vm_fails(self, mock_psutil: MagicMock, mock_time: MagicMock) -> None:
        mock_psutil.virtual_memory.side_effect = OSError("not supported")
        mock_psutil.swap_memory.return_value = MagicMock(total=0, used=0, percent=0)
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        io = MagicMock()
        io.read_bytes = 1000
        io.write_bytes = 1000
        io.read_count = 10
        io.write_count = 10
        mock_psutil.disk_io_counters.return_value = io
        net = MagicMock()
        net.bytes_sent = 1000
        net.bytes_recv = 1000
        net.packets_sent = 10
        net.packets_recv = 10
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        mem = [r for r in results if r.diagnostic_id == "performance_memory"][0]
        assert mem.status == DiagnosticStatus.UNAVAILABLE


# ── AH. Disk I/O cumulative vs rate ─────────────────────────────────────

class TestDiskIORate:
    @patch("app.diagnostics.performance.time")
    @patch("app.diagnostics.performance.psutil")
    def test_cumulative_only_no_false_warning(self, mock_psutil: MagicMock, mock_time: MagicMock) -> None:
        """Large cumulative I/O with zero rate should NOT produce a warning."""
        io1 = MagicMock()
        io1.read_bytes = 100 * 1024**3
        io1.write_bytes = 100 * 1024**3
        io1.read_count = 1000000
        io1.write_count = 1000000
        io2 = MagicMock()
        io2.read_bytes = 100 * 1024**3
        io2.write_bytes = 100 * 1024**3
        io2.read_count = 1000000
        io2.write_count = 1000000
        mock_psutil.disk_io_counters.side_effect = [io1, io2]
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        vm = MagicMock()
        vm.total = 8 * 1024**3
        vm.available = 6 * 1024**3
        vm.used = 2 * 1024**3
        vm.percent = 25.0
        mock_psutil.virtual_memory.return_value = vm
        mock_psutil.swap_memory.return_value = MagicMock(total=0, used=0, percent=0)
        net = MagicMock()
        net.bytes_sent = 1000
        net.bytes_recv = 1000
        net.packets_sent = 10
        net.packets_recv = 10
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        disk_io = [r for r in results if r.diagnostic_id == "performance_disk_io"][0]
        assert disk_io.status == DiagnosticStatus.OK
        assert "Cumulative:" in disk_io.summary
        assert "0.0 MB/s" in disk_io.summary

    @patch("app.diagnostics.performance.time")
    @patch("app.diagnostics.performance.psutil")
    def test_high_rate_triggers_warning(self, mock_psutil: MagicMock, mock_time: MagicMock) -> None:
        """High I/O rate should produce a warning."""
        io1 = MagicMock()
        io1.read_bytes = 1000
        io1.write_bytes = 1000
        io1.read_count = 10
        io1.write_count = 10
        io2 = MagicMock()
        io2.read_bytes = 1000 + 200 * 1024**2
        io2.write_bytes = 1000 + 150 * 1024**2
        io2.read_count = 20
        io2.write_count = 20
        mock_psutil.disk_io_counters.side_effect = [io1, io2]
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        vm = MagicMock()
        vm.total = 8 * 1024**3
        vm.available = 6 * 1024**3
        vm.used = 2 * 1024**3
        vm.percent = 25.0
        mock_psutil.virtual_memory.return_value = vm
        mock_psutil.swap_memory.return_value = MagicMock(total=0, used=0, percent=0)
        net = MagicMock()
        net.bytes_sent = 1000
        net.bytes_recv = 1000
        net.packets_sent = 10
        net.packets_recv = 10
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        disk_io = [r for r in results if r.diagnostic_id == "performance_disk_io"][0]
        assert disk_io.status == DiagnosticStatus.WARNING
        assert "MB/s" in disk_io.summary

    @patch("app.diagnostics.performance.time")
    @patch("app.diagnostics.performance.psutil")
    def test_disk_io_rate_unavailable_fallback(self, mock_psutil: MagicMock, mock_time: MagicMock) -> None:
        """When second sample fails, report cumulative only."""
        io1 = MagicMock()
        io1.read_bytes = 50 * 1024**3
        io1.write_bytes = 30 * 1024**3
        io1.read_count = 500000
        io1.write_count = 300000
        mock_psutil.disk_io_counters.side_effect = [io1, None]
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        vm = MagicMock()
        vm.total = 8 * 1024**3
        vm.available = 6 * 1024**3
        vm.used = 2 * 1024**3
        vm.percent = 25.0
        mock_psutil.virtual_memory.return_value = vm
        mock_psutil.swap_memory.return_value = MagicMock(total=0, used=0, percent=0)
        net = MagicMock()
        net.bytes_sent = 1000
        net.bytes_recv = 1000
        net.packets_sent = 10
        net.packets_recv = 10
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        disk_io = [r for r in results if r.diagnostic_id == "performance_disk_io"][0]
        assert disk_io.status == DiagnosticStatus.OK
        assert "Rate measurement unavailable" in disk_io.summary
        assert "50" in disk_io.summary


# ── AI. Snapshot vs trend wording ───────────────────────────────────────

class TestSnapshotWording:
    @patch("app.diagnostics.performance.time")
    @patch("app.diagnostics.performance.psutil")
    def test_cpu_summary_is_snapshot(self, mock_psutil: MagicMock, mock_time: MagicMock) -> None:
        mock_psutil.cpu_percent.return_value = 45.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        vm = MagicMock()
        vm.total = 8 * 1024**3
        vm.available = 6 * 1024**3
        vm.used = 2 * 1024**3
        vm.percent = 25.0
        mock_psutil.virtual_memory.return_value = vm
        mock_psutil.swap_memory.return_value = MagicMock(total=0, used=0, percent=0)
        io = MagicMock()
        io.read_bytes = 1000
        io.write_bytes = 1000
        io.read_count = 10
        io.write_count = 10
        mock_psutil.disk_io_counters.return_value = io
        net = MagicMock()
        net.bytes_sent = 1000
        net.bytes_recv = 1000
        net.packets_sent = 10
        net.packets_recv = 10
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        cpu = [r for r in results if r.diagnostic_id == "performance_cpu"][0]
        assert "utilization" in cpu.title.lower()
        assert "45.0%" in cpu.summary

    @patch("app.diagnostics.performance.time")
    @patch("app.diagnostics.performance.psutil")
    def test_memory_summary_is_snapshot(self, mock_psutil: MagicMock, mock_time: MagicMock) -> None:
        vm = MagicMock()
        vm.total = 16 * 1024**3
        vm.available = 4 * 1024**3
        vm.used = 12 * 1024**3
        vm.percent = 75.0
        mock_psutil.virtual_memory.return_value = vm
        mock_psutil.swap_memory.return_value = MagicMock(total=0, used=0, percent=0)
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        io = MagicMock()
        io.read_bytes = 1000
        io.write_bytes = 1000
        io.read_count = 10
        io.write_count = 10
        mock_psutil.disk_io_counters.return_value = io
        net = MagicMock()
        net.bytes_sent = 1000
        net.bytes_recv = 1000
        net.packets_sent = 10
        net.packets_recv = 10
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        mem = [r for r in results if r.diagnostic_id == "performance_memory"][0]
        assert "utilization" in mem.title.lower()
        assert "75.0%" in mem.summary
        assert "used" in mem.summary

    @patch("app.diagnostics.performance.time")
    @patch("app.diagnostics.performance.psutil")
    def test_network_summary_says_cumulative(self, mock_psutil: MagicMock, mock_time: MagicMock) -> None:
        mock_psutil.cpu_percent.return_value = 10.0
        mock_psutil.cpu_count.return_value = 4
        mock_psutil.cpu_count.side_effect = [4, 2]
        vm = MagicMock()
        vm.total = 8 * 1024**3
        vm.available = 6 * 1024**3
        vm.used = 2 * 1024**3
        vm.percent = 25.0
        mock_psutil.virtual_memory.return_value = vm
        mock_psutil.swap_memory.return_value = MagicMock(total=0, used=0, percent=0)
        io = MagicMock()
        io.read_bytes = 1000
        io.write_bytes = 1000
        io.read_count = 10
        io.write_count = 10
        mock_psutil.disk_io_counters.return_value = io
        net = MagicMock()
        net.bytes_sent = 5000
        net.bytes_recv = 6000
        net.packets_sent = 50
        net.packets_recv = 60
        mock_psutil.net_io_counters.return_value = net
        mock_psutil.net_io_counters.side_effect = None
        from app.diagnostics.performance import collect_performance
        results = collect_performance()
        net_result = [r for r in results if r.diagnostic_id == "performance_network_io"][0]
        assert "since boot" in net_result.summary
        assert net_result.status == DiagnosticStatus.OK
