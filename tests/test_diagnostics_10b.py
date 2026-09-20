"""Tests for Phase 10B diagnostic modules (event_log, reliability, boot_timing, network_health, driver_consistency)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticRun, DiagnosticStatus


# ── Event log diagnostics ──────────────────────────────────────────────

class TestEventLogDiagnostics:
    @patch("app.diagnostics.event_log.run_powershell")
    def test_event_log_system_errors(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total": 15,
            "sources": [
                {"name": "Service Control Manager", "count": 10},
                {"name": "DistributedCOM", "count": 5},
            ]
        }, None)
        from app.diagnostics.event_log import collect_event_log
        results = collect_event_log()
        sys_errors = [r for r in results if r.diagnostic_id == "event_log_system_errors"]
        assert len(sys_errors) == 1
        assert sys_errors[0].status == DiagnosticStatus.WARNING
        assert "15" in sys_errors[0].summary

    @patch("app.diagnostics.event_log.run_powershell")
    def test_event_log_app_crashes(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total": 5,
            "sources": [{"name": "MyApp", "count": 5}]
        }, None)
        from app.diagnostics.event_log import collect_event_log
        results = collect_event_log()
        app_crashes = [r for r in results if r.diagnostic_id == "event_log_app_crashes"]
        assert len(app_crashes) == 1
        assert app_crashes[0].status == DiagnosticStatus.WARNING

    @patch("app.diagnostics.event_log.run_powershell")
    def test_event_log_recurring_detection(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total": 20,
            "sources": [{"name": "Service Control Manager", "count": 15}]
        }, None)
        from app.diagnostics.event_log import collect_event_log
        results = collect_event_log()
        recurring = [r for r in results if r.diagnostic_id == "event_log_recurring"]
        assert len(recurring) == 1
        assert recurring[0].status == DiagnosticStatus.WARNING

    @patch("app.diagnostics.event_log.run_powershell")
    def test_event_log_no_recurring(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total": 2,
            "sources": [{"name": "RareSource", "count": 1}]
        }, None)
        from app.diagnostics.event_log import collect_event_log
        results = collect_event_log()
        recurring = [r for r in results if r.diagnostic_id == "event_log_recurring"]
        assert len(recurring) == 1
        assert recurring[0].status == DiagnosticStatus.OK

    @patch("app.diagnostics.event_log.run_powershell")
    def test_event_log_powershell_error(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = (None, "Access denied")
        from app.diagnostics.event_log import collect_event_log
        results = collect_event_log()
        assert any(r.status == DiagnosticStatus.UNAVAILABLE for r in results)


# ── Reliability diagnostics ────────────────────────────────────────────

class TestReliabilityDiagnostics:
    @patch("app.diagnostics.reliability.run_powershell")
    def test_reliability_summary_ok(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total": 2,
            "by_type": [{"name": "Application Crash", "count": 2}],
            "by_source": [{"name": "MyApp", "count": 2}],
            "app_failures": [],
            "update_failures": [],
        }, None)
        from app.diagnostics.reliability import collect_reliability
        results = collect_reliability()
        summary = [r for r in results if r.diagnostic_id == "reliability_summary"]
        assert len(summary) == 1
        assert summary[0].status == DiagnosticStatus.OK

    @patch("app.diagnostics.reliability.run_powershell")
    def test_reliability_summary_warning(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total": 5,
            "by_type": [{"name": "Application Crash", "count": 5}],
            "by_source": [],
            "app_failures": [],
            "update_failures": [],
        }, None)
        from app.diagnostics.reliability import collect_reliability
        results = collect_reliability()
        summary = [r for r in results if r.diagnostic_id == "reliability_summary"]
        assert len(summary) == 1
        assert summary[0].status == DiagnosticStatus.WARNING

    @patch("app.diagnostics.reliability.run_powershell")
    def test_reliability_app_failures(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total": 0,
            "by_type": [],
            "by_source": [],
            "app_failures": [{"name": "MyApp", "count": 3}],
            "update_failures": [],
        }, None)
        from app.diagnostics.reliability import collect_reliability
        results = collect_reliability()
        failures = [r for r in results if r.diagnostic_id == "reliability_app_failures"]
        assert len(failures) == 1
        assert failures[0].status == DiagnosticStatus.WARNING

    @patch("app.diagnostics.reliability.run_powershell")
    def test_reliability_update_failures(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total": 0,
            "by_type": [],
            "by_source": [],
            "app_failures": [],
            "update_failures": [],
        }, None)
        from app.diagnostics.reliability import collect_reliability
        results = collect_reliability()
        updates = [r for r in results if r.diagnostic_id == "reliability_update_failures"]
        assert len(updates) == 1
        assert updates[0].status == DiagnosticStatus.OK


# ── Boot timing diagnostics ────────────────────────────────────────────

class TestBootTimingDiagnostics:
    @patch("app.diagnostics.boot_timing.run_powershell")
    def test_boot_timing_startup_programs(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "user_count": 10,
            "machine_count": 4,
            "total": 14,
        }, None)
        from app.diagnostics.boot_timing import collect_boot_timing
        results = collect_boot_timing()
        startup = [r for r in results if r.diagnostic_id == "boot_timing_startup_programs"]
        assert len(startup) == 1
        assert "14" in startup[0].summary
        assert startup[0].status == DiagnosticStatus.OK

    def test_boot_time_from_psutil(self) -> None:
        from app.diagnostics.boot_timing import collect_boot_timing
        results = collect_boot_timing()
        boot_time = [r for r in results if r.diagnostic_id == "boot_timing_boot_time"]
        assert len(boot_time) == 1
        assert boot_time[0].status == DiagnosticStatus.OK
        assert "uptime" in boot_time[0].summary.lower()


# ── Network health diagnostics ─────────────────────────────────────────

class TestNetworkHealthDiagnostics:
    @patch("app.diagnostics.network_health._check_dns_resolution")
    @patch("app.diagnostics.network_health._collect_dns_configuration")
    @patch("app.diagnostics.network_health.psutil")
    def test_network_health_adapters(self, mock_psutil: MagicMock, mock_dns_cfg: MagicMock, mock_dns: MagicMock) -> None:
        # Mock psutil adapter status
        mock_stat1 = MagicMock()
        mock_stat1.isup = True
        mock_stat2 = MagicMock()
        mock_stat2.isup = True
        mock_stat3 = MagicMock()
        mock_stat3.isup = False
        mock_psutil.net_if_stats.return_value = {"Wi-Fi": mock_stat1, "Ethernet": mock_stat2, "VPN": mock_stat3}
        mock_dns_cfg.return_value = {"configured": True, "entries": [{"interface": "Wi-Fi", "servers": "8.8.8.8"}]}
        mock_dns.return_value = {"resolved": True, "server": "dns.google", "ip": "8.8.4.4"}
        from app.diagnostics.network_health import collect_network_health
        results = collect_network_health()
        adapters = [r for r in results if r.diagnostic_id == "network_health_adapter_status"]
        assert len(adapters) == 1
        assert "2 up" in adapters[0].summary

    @patch("app.diagnostics.network_health._check_dns_resolution")
    @patch("app.diagnostics.network_health._collect_dns_configuration")
    @patch("app.diagnostics.network_health.psutil")
    def test_network_health_dns_resolution_fail(self, mock_psutil: MagicMock, mock_dns_cfg: MagicMock, mock_dns: MagicMock) -> None:
        mock_stat = MagicMock()
        mock_stat.isup = True
        mock_psutil.net_if_stats.return_value = {"Wi-Fi": mock_stat}
        mock_dns_cfg.return_value = {"configured": True, "entries": []}
        mock_dns.return_value = {"resolved": False, "server": "dns.google", "ip": None}
        from app.diagnostics.network_health import collect_network_health
        results = collect_network_health()
        dns_res = [r for r in results if r.diagnostic_id == "network_health_dns_resolution"]
        assert len(dns_res) == 1
        assert dns_res[0].status == DiagnosticStatus.WARNING

    def test_dns_resolution_real(self) -> None:
        from app.diagnostics.network_health import _check_dns_resolution
        result = _check_dns_resolution()
        assert "resolved" in result
        assert isinstance(result["resolved"], bool)


# ── Driver consistency diagnostics ─────────────────────────────────────

class TestDriverConsistencyDiagnostics:
    @patch("app.diagnostics.driver_consistency.run_powershell")
    def test_driver_age_ok(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total_drivers": 50, "with_date": 50, "outdated_count": 0,
            "outdated_top": [], "error_total": 0, "by_error": [],
        }, None)
        from app.diagnostics.driver_consistency import collect_driver_consistency
        results = collect_driver_consistency()
        age = [r for r in results if r.diagnostic_id == "driver_consistency_age"]
        assert len(age) == 1
        assert age[0].status == DiagnosticStatus.OK

    @patch("app.diagnostics.driver_consistency.run_powershell")
    def test_driver_age_warning(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total_drivers": 50, "with_date": 50, "outdated_count": 5,
            "outdated_top": [{"name": "OldDriver", "version": "1.0", "date": "2020-01-01", "age_days": 2000}],
            "error_total": 0, "by_error": [],
        }, None)
        from app.diagnostics.driver_consistency import collect_driver_consistency
        results = collect_driver_consistency()
        age = [r for r in results if r.diagnostic_id == "driver_consistency_age"]
        assert len(age) == 1
        assert age[0].status == DiagnosticStatus.WARNING

    @patch("app.diagnostics.driver_consistency.run_powershell")
    def test_driver_errors_ok(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total_drivers": 50, "with_date": 50, "outdated_count": 0,
            "outdated_top": [], "error_total": 0, "by_error": [],
        }, None)
        from app.diagnostics.driver_consistency import collect_driver_consistency
        results = collect_driver_consistency()
        errors = [r for r in results if r.diagnostic_id == "driver_consistency_errors"]
        assert len(errors) == 1
        assert errors[0].status == DiagnosticStatus.OK

    @patch("app.diagnostics.driver_consistency.run_powershell")
    def test_driver_errors_warning(self, mock_ps: MagicMock) -> None:
        mock_ps.return_value = ({
            "total_drivers": 50, "with_date": 50, "outdated_count": 0,
            "outdated_top": [], "error_total": 3,
            "by_error": [{"code": 10, "count": 2}, {"code": 28, "count": 1}],
        }, None)
        from app.diagnostics.driver_consistency import collect_driver_consistency
        results = collect_driver_consistency()
        errors = [r for r in results if r.diagnostic_id == "driver_consistency_errors"]
        assert len(errors) == 1
        assert errors[0].status == DiagnosticStatus.WARNING


# ── New categories in DiagnosticCategory ───────────────────────────────

class TestNewDiagnosticCategories:
    def test_new_categories_exist(self) -> None:
        assert DiagnosticCategory.EVENT_LOG.value == "event_log"
        assert DiagnosticCategory.RELIABILITY.value == "reliability"
        assert DiagnosticCategory.BOOT_TIMING.value == "boot_timing"
        assert DiagnosticCategory.NETWORK_HEALTH.value == "network_health"
        assert DiagnosticCategory.DRIVER_CONSISTENCY.value == "driver_consistency"

    def test_runner_includes_new_collectors(self) -> None:
        from app.diagnostics.runner import run_diagnostics
        import inspect
        source = inspect.getsource(run_diagnostics)
        assert "collect_event_log" in source
        assert "collect_reliability" in source
        assert "collect_boot_timing" in source
        assert "collect_network_health" in source
        assert "collect_driver_consistency" in source


# ── DiagnosticRun properties for new categories ────────────────────────

class TestDiagnosticRunNewProperties:
    def test_event_log_results_property(self) -> None:
        run = DiagnosticRun(
            results=[
                DiagnosticResult(
                    diagnostic_id="test", category=DiagnosticCategory.EVENT_LOG,
                    status=DiagnosticStatus.OK, title="Test", summary="Test",
                )
            ]
        )
        assert len(run.event_log_results) == 1

    def test_reliability_results_property(self) -> None:
        run = DiagnosticRun(
            results=[
                DiagnosticResult(
                    diagnostic_id="test", category=DiagnosticCategory.RELIABILITY,
                    status=DiagnosticStatus.OK, title="Test", summary="Test",
                )
            ]
        )
        assert len(run.reliability_results) == 1

    def test_boot_timing_results_property(self) -> None:
        run = DiagnosticRun(
            results=[
                DiagnosticResult(
                    diagnostic_id="test", category=DiagnosticCategory.BOOT_TIMING,
                    status=DiagnosticStatus.OK, title="Test", summary="Test",
                )
            ]
        )
        assert len(run.boot_timing_results) == 1

    def test_network_health_results_property(self) -> None:
        run = DiagnosticRun(
            results=[
                DiagnosticResult(
                    diagnostic_id="test", category=DiagnosticCategory.NETWORK_HEALTH,
                    status=DiagnosticStatus.OK, title="Test", summary="Test",
                )
            ]
        )
        assert len(run.network_health_results) == 1

    def test_driver_consistency_results_property(self) -> None:
        run = DiagnosticRun(
            results=[
                DiagnosticResult(
                    diagnostic_id="test", category=DiagnosticCategory.DRIVER_CONSISTENCY,
                    status=DiagnosticStatus.OK, title="Test", summary="Test",
                )
            ]
        )
        assert len(run.driver_consistency_results) == 1
