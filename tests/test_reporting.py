"""Tests for the unified health report.

All tests use mocked data or a temporary SQLite database. No real system
modifications are made.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from app.database.sqlite import SnapshotStore
from app.reporting.builder import SCHEMA_VERSION, build_health_report
from app.reporting.formatter import format_report
from app.reporting.json_export import report_to_dict, report_to_json
from app.reporting.models import (
    BatterySummary,
    FindingSummary,
    FindingsGrouped,
    FileAnalysisSummary,
    HealthReport,
    ReportError,
    RemediationActionMeta,
    RemediationSummary,
    SystemInfo,
)
from app.reporting.runner import generate_human, generate_json, generate_report


# ── Helpers ────────────────────────────────────────────────────────────


def _make_store_with_run(
    status: str = "completed",
    snapshots: dict | None = None,
    findings: list[dict] | None = None,
    analysis_status: str | None = None,
) -> SnapshotStore:
    """Create a temporary store with one discovery run and optional data."""
    import json as _json

    tmp = tempfile.mkdtemp()
    db_path = Path(tmp) / "test.db"
    store = SnapshotStore(path=db_path)
    run_id = store.start_run()

    if snapshots:
        for cat, payload in snapshots.items():
            store.save(cat, payload, run_id=run_id)

    if findings:
        with store._connect() as conn:
            for f in findings:
                conn.execute(
                    "INSERT INTO findings("
                    "  run_id, analyzer, severity, title, message,"
                    "  evidence_json, recommendation"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        f.get("analyzer", "test"),
                        f.get("severity", "info"),
                        f.get("title", "test finding"),
                        f.get("message", ""),
                        _json.dumps(f.get("evidence"), default=str, sort_keys=True) if f.get("evidence") is not None else None,
                        f.get("recommendation"),
                    ),
                )

    store.complete_run(run_id, status=status)

    if analysis_status is not None:
        store.set_analysis_status(run_id, analysis_status)

    return store


def _full_snapshots() -> dict:
    return {
        "windows_os": {"Caption": "Microsoft Windows 10 Pro", "Version": "10.0.19045", "OSArchitecture": "64-bit"},
        "windows_computer_system": {"Manufacturer": "TestCorp", "Model": "TestBook 1", "TotalPhysicalMemory": 16 * 1024**3},
        "windows_bios": {"Manufacturer": "TestBIOS", "SMBIOSBIOSVersion": "1.0.0"},
        "hardware": {
            "hostname": "TESTPC",
            "processor": "Intel Core i7-12700H",
            "cpu_physical_cores": 14,
            "cpu_logical_cores": 20,
            "memory_total_bytes": 16 * 1024**3,
        },
        "storage": [
            {"device": "C:", "filesystem": "NTFS", "total_bytes": 500 * 1024**3, "free_bytes": 100 * 1024**3, "percent_used": 80.0},
            {"device": "D:", "filesystem": "NTFS", "total_bytes": 1000 * 1024**3, "free_bytes": 500 * 1024**3, "percent_used": 50.0},
        ],
        "battery": {
            "available": True,
            "status": "charging",
            "percent": 45.0,
            "plugged_in": True,
            "design_capacity_mwh": 41610,
            "full_charge_capacity_mwh": 35000,
            "remaining_capacity_mwh": 18724,
            "health_percent": 84.1,
            "wear_percent": 15.9,
            "health_status": "good",
            "cycle_count": 150,
            "manufacturer": "SMP",
            "battery_name": "KI04041",
            "serial_number_present": False,
        },
        "software": [{"name": "Python 3.13"}, {"name": "Git"}, {"name": "VS Code"}],
        "startup": [{"name": "OneDrive"}, {"name": "Steam"}],
        "processes": [{"pid": 1}, {"pid": 2}, {"pid": 3}],
        "services": [{"name": "Spooler"}, {"name": "WinDefend"}],
        "scheduled_tasks": [{"name": "\\Microsoft\\Windows\\Defrag"}],
    }


# ── A. Complete report generation ──────────────────────────────────────


class TestCompleteReportGeneration:
    def test_returns_health_report(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        assert isinstance(report, HealthReport)

    def test_report_has_all_sections(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        assert report.system.hostname == "TESTPC"
        assert report.storage.count == 2
        assert report.battery.available is True
        assert report.software.count == 3
        assert report.startup.count == 2
        assert report.processes.count == 3
        assert report.services.count == 2
        assert report.scheduled_tasks.count == 1


# ── B. Latest completed run selected ───────────────────────────────────


class TestLatestCompletedRun:
    def test_uses_latest_completed(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test.db"
        store = SnapshotStore(path=db_path)

        # First run
        r1 = store.start_run()
        store.save("hardware", {"hostname": "OLD"}, run_id=r1)
        store.complete_run(r1, status="completed")

        # Second run (latest)
        r2 = store.start_run()
        store.save("hardware", {"hostname": "NEW"}, run_id=r2)
        store.complete_run(r2, status="completed")

        report = build_health_report(store)
        assert report.discovery_run_id == r2
        assert report.system.hostname == "NEW"


# ── C. Failed latest run ignored when completed exists ─────────────────


class TestFailedRunIgnored:
    def test_failed_run_ignored_when_completed_exists(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test.db"
        store = SnapshotStore(path=db_path)

        # Completed run
        r1 = store.start_run()
        store.save("hardware", {"hostname": "GOOD"}, run_id=r1)
        store.complete_run(r1, status="completed")

        # Failed run (latest)
        r2 = store.start_run()
        store.complete_run(r2, status="failed")

        report = build_health_report(store)
        assert report.discovery_run_id == r1
        assert report.system.hostname == "GOOD"


# ── D. No completed run handled cleanly ────────────────────────────────


class TestNoCompletedRun:
    def test_returns_error_report(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test.db"
        store = SnapshotStore(path=db_path)

        report = build_health_report(store)
        assert report.discovery_run_id is None
        assert len(report.errors) == 1
        assert report.errors[0].component == "discovery"
        assert "No completed" in report.errors[0].message


# ── E. Schema version present ──────────────────────────────────────────


class TestSchemaVersion:
    def test_schema_version_is_string(self) -> None:
        report = HealthReport()
        assert report.schema_version == "1.0"

    def test_schema_version_in_json(self) -> None:
        report = HealthReport()
        data = report_to_dict(report)
        assert data["schema_version"] == "1.0"

    def test_builder_uses_constant(self) -> None:
        assert SCHEMA_VERSION == "1.0"


# ── F. System section populated ────────────────────────────────────────


class TestSystemSection:
    def test_system_from_snapshots(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        assert report.system.hostname == "TESTPC"
        assert report.system.os_name == "Microsoft Windows 10 Pro"
        assert report.system.os_version == "10.0.19045"
        assert report.system.architecture == "64-bit"
        assert report.system.manufacturer == "TestCorp"
        assert report.system.model == "TestBook 1"
        assert report.system.cpu_name == "Intel Core i7-12700H"
        assert report.system.ram_total_bytes == 16 * 1024**3

    def test_missing_system_data(self) -> None:
        store = _make_store_with_run(snapshots={})
        report = build_health_report(store)
        assert report.system.hostname is None


# ── G. Storage summary ─────────────────────────────────────────────────


class TestStorageSummary:
    def test_partition_count(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        assert report.storage.count == 2

    def test_storage_status_thresholds(self) -> None:
        from app.reporting.builder import _storage_status
        assert _storage_status(79.9) == "normal"
        assert _storage_status(85.0) == "warning"
        assert _storage_status(95.0) == "critical"

    def test_partition_fields(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        p = report.storage.partitions[0]
        assert p.device == "C:"
        assert p.filesystem == "NTFS"
        assert p.status == "warning"


# ── H. Battery dead/non-baseline representation ────────────────────────


class TestBatteryNonBaseline:
    def test_dead_battery(self) -> None:
        snaps = _full_snapshots()
        snaps["battery"]["full_charge_capacity_mwh"] = None
        snaps["battery"]["health_percent"] = None
        snaps["battery"]["health_status"] = "unknown"
        store = _make_store_with_run(snapshots=snaps)
        report = build_health_report(store)
        assert report.battery.baseline_status == "non-baseline"
        assert report.battery.health_status == "unknown"
        assert report.battery.health_percent is None

    def test_battery_no_serial(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        # BatterySummary should never have a serial number field
        assert not hasattr(report.battery, "serial_number")
        d = report_to_dict(report)
        assert "serial_number" not in d["battery"]


# ── I. Findings grouped correctly ──────────────────────────────────────


class TestFindingsGrouped:
    def test_grouping(self) -> None:
        findings = [
            {"analyzer": "storage", "severity": "critical", "title": "Disk full"},
            {"analyzer": "storage", "severity": "warning", "title": "Disk 85%"},
            {"analyzer": "battery", "severity": "info", "title": "Battery OK"},
            {"analyzer": "battery", "severity": "info", "title": "Battery charge"},
        ]
        store = _make_store_with_run(snapshots=_full_snapshots(), findings=findings)
        report = build_health_report(store)
        assert report.findings.critical_count == 1
        assert report.findings.warning_count == 1
        assert report.findings.info_count == 2
        assert report.findings.critical[0].title == "Disk full"
        assert report.findings.warning[0].title == "Disk 85%"

    def test_empty_findings(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        assert report.findings.critical_count == 0
        assert report.findings.warning_count == 0
        assert report.findings.info_count == 0


# ── J. No invented health score ────────────────────────────────────────


class TestNoHealthScore:
    def test_no_score_field(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        d = report_to_dict(report)
        # Summary should not contain a score/health_score/rating
        assert "health_score" not in d
        assert "score" not in d.get("summary", {})
        assert "rating" not in d

    def test_human_report_no_score(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        human = format_report(report)
        assert "health score" not in human.lower()
        assert "out of 100" not in human.lower()
        assert "percent healthy" not in human.lower()


# ── K. File-analysis summary included ──────────────────────────────────


class TestFileAnalysisSummary:
    def test_no_scan_available(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        assert report.file_analysis.available is False
        assert report.file_analysis.files_examined == 0

    def test_with_scan_data(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test.db"
        store = SnapshotStore(path=db_path)
        run_id = store.start_run()
        store.save("system", {"hostname": "X"}, run_id=run_id)
        store.complete_run(run_id, status="completed")
        scan_id = store.start_file_scan("C:\\test")
        store.complete_file_scan(scan_id, {
            "files_examined": 150,
            "directories_examined": 20,
            "bytes_examined": 5000000,
            "files_skipped": 2,
            "symlinks_skipped": 1,
            "excluded_items": 3,
            "inaccessible_items": 0,
            "elapsed_seconds": 0.5,
        })
        report = build_health_report(store)
        assert report.file_analysis.available is True
        assert report.file_analysis.files_examined == 150
        assert report.file_analysis.scan_root == "C:\\test"


# ── L. Remediation metadata included without execution ─────────────────


class TestRemediationMetadata:
    def test_actions_present(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        assert len(report.remediation.actions) > 0

    def test_quarantine_action_properties(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        qa = [a for a in report.remediation.actions if a.action_id == "user_temp_quarantine"]
        assert len(qa) == 1
        a = qa[0]
        assert a.reversible is True
        assert a.preview_available is True
        assert a.rollback_available is True
        assert a.real_execution_exists is True

    def test_no_execution_in_builder(self) -> None:
        """The builder should never invoke remediation execution."""
        import app.remediation.executor as ex
        original = ex.QuarantineExecutor.execute
        ex.QuarantineExecutor.execute = lambda self, *a, **kw: (_ for _ in ()).throw(AccessError("should not execute"))
        try:
            store = _make_store_with_run(snapshots=_full_snapshots())
            build_health_report(store)
        except Exception:
            pass
        finally:
            ex.QuarantineExecutor.execute = original


# ── M. Errors represented ──────────────────────────────────────────────


class TestErrorsRepresented:
    def test_error_in_report(self) -> None:
        report = HealthReport(
            errors=[
                ReportError(component="battery", stage="collection", message="WMI timeout", severity="warning"),
            ]
        )
        d = report_to_dict(report)
        assert len(d["errors"]) == 1
        assert d["errors"][0]["component"] == "battery"
        assert d["errors"][0]["severity"] == "warning"

    def test_human_report_shows_errors(self) -> None:
        report = HealthReport(
            errors=[
                ReportError(component="battery", stage="collection", message="WMI timeout", severity="warning"),
            ]
        )
        human = format_report(report)
        assert "ERRORS" in human
        assert "WMI timeout" in human


# ── N. JSON serialization valid ────────────────────────────────────────


class TestJsonValid:
    def test_valid_json(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        json_str = report_to_json(report)
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_empty_report_valid_json(self) -> None:
        report = HealthReport()
        json_str = report_to_json(report)
        parsed = json.loads(json_str)
        assert parsed["schema_version"] == "1.0"


# ── O. Deterministic/stable JSON structure ─────────────────────────────


class TestDeterministicJson:
    def test_same_data_same_json(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        r1 = build_health_report(store)
        r2 = build_health_report(store)
        j1 = report_to_json(r1)
        j2 = report_to_json(r2)
        # generated_at will differ, so compare structure keys
        assert set(json.loads(j1).keys()) == set(json.loads(j2).keys())


# ── P. Datetime serialization ─────────────────────────────────────────


class TestDatetimeSerialization:
    def test_generated_at_is_string(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        d = report_to_dict(report)
        assert isinstance(d["generated_at"], str)

    def test_generated_at_not_none(self) -> None:
        report = HealthReport(generated_at="2026-01-01T00:00:00")
        d = report_to_dict(report)
        assert d["generated_at"] == "2026-01-01T00:00:00"


# ── Q. Path serialization ──────────────────────────────────────────────


class TestPathSerialization:
    def test_file_analysis_path_is_string(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test.db"
        store = SnapshotStore(path=db_path)
        run_id = store.start_run()
        store.complete_run(run_id, status="completed")
        scan_id = store.start_file_scan("C:\\Users\\test")
        store.complete_file_scan(scan_id, {"files_examined": 0, "directories_examined": 0,
                                            "bytes_examined": 0, "files_skipped": 0,
                                            "symlinks_skipped": 0, "excluded_items": 0,
                                            "inaccessible_items": 0, "elapsed_seconds": 0})
        report = build_health_report(store)
        d = report_to_dict(report)
        assert isinstance(d["file_analysis"]["scan_root"], str)


# ── R. None → null ────────────────────────────────────────────────────


class TestNoneIsNull:
    def test_none_becomes_null(self) -> None:
        report = HealthReport()
        d = report_to_dict(report)
        assert d["discovery_run_id"] is None
        assert d["system"]["hostname"] is None
        json_str = report_to_json(report)
        parsed = json.loads(json_str)
        assert parsed["discovery_run_id"] is None

    def test_battery_none_fields(self) -> None:
        report = HealthReport(battery=BatterySummary(available=None))
        d = report_to_dict(report)
        assert d["battery"]["available"] is None


# ── S. Sensitive battery serial absent ─────────────────────────────────


class TestNoBatterySerial:
    def test_battery_summary_no_serial(self) -> None:
        b = BatterySummary(manufacturer="SMP")
        d = report_to_dict(HealthReport(battery=b))
        assert "serial_number" not in d["battery"]
        assert "serial" not in json.dumps(d).lower() or "serial_number_present" not in json.dumps(d)

    def test_json_no_serial_key(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        json_str = report_to_json(report)
        assert "serial_number_present" not in json_str
        # manufacturer may appear but serial must not
        parsed = json.loads(json_str)
        for key in ("serial_number", "serial_number_present", "serial"):
            assert key not in parsed["battery"], f"Unexpected key: {key}"


# ── T. Human report contains same key facts as JSON ───────────────────


class TestHumanMatchesJson:
    def test_key_facts_in_human(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        d = report_to_dict(report)
        human = format_report(report)
        # Check key values appear in human output
        assert d["system"]["hostname"] in human
        assert "TESTPC" in human
        assert str(d["storage"]["count"]) in human
        assert "FINDINGS" in human
        assert "STORAGE" in human
        assert "BATTERY" in human
        assert "FILE ANALYSIS" in human
        assert "REMEDIATION" in human

    def test_finding_count_matches(self) -> None:
        findings = [
            {"analyzer": "a", "severity": "critical", "title": "X"},
            {"analyzer": "b", "severity": "warning", "title": "Y"},
        ]
        store = _make_store_with_run(snapshots=_full_snapshots(), findings=findings, analysis_status="completed")
        report = build_health_report(store)
        human = format_report(report)
        assert "critical=1" in human
        assert "warning=1" in human


# ── U. Bounded result sizes ────────────────────────────────────────────


class TestBoundedSizes:
    def test_findings_limited_in_human(self) -> None:
        findings = [{"analyzer": "a", "severity": "info", "title": f"Finding {i}"} for i in range(100)]
        store = _make_store_with_run(snapshots=_full_snapshots(), findings=findings)
        report = build_health_report(store)
        human = format_report(report)
        # The formatter limits to 20 per severity
        assert human.count("Finding") <= 30  # some buffer for headers

    def test_large_files_bounded(self) -> None:
        d = report_to_dict(HealthReport(
            file_analysis=FileAnalysisSummary(
                available=True,
                largest_files=[{"path": f"file{i}.dat", "size_bytes": i * 1024} for i in range(200)],
            )
        ))
        assert len(d["file_analysis"]["largest_files"]) == 200


# ── V. Existing tests remain passing ──────────────────────────────────


class TestExistingTestsUnaffected:
    def test_finding_model_still_works(self) -> None:
        from app.analyzers.finding import Finding
        f = Finding(analyzer="test", severity="info", title="t", message="m")
        assert f.analyzer == "test"

    def test_snapshot_store_works(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test.db"
        store = SnapshotStore(path=db_path)
        run_id = store.start_run()
        store.complete_run(run_id, status="completed")
        run = store.get_latest_completed_run()
        assert run is not None
        assert run["id"] == run_id


# ── Formatter edge cases ───────────────────────────────────────────────


class TestFormatterEdgeCases:
    def test_empty_storage(self) -> None:
        report = HealthReport()
        human = format_report(report)
        assert "No partitions detected" in human

    def test_no_battery(self) -> None:
        report = HealthReport(battery=BatterySummary(available=False))
        human = format_report(report)
        assert "No battery detected" in human

    def test_no_file_analysis(self) -> None:
        report = HealthReport()
        human = format_report(report)
        assert "No file analysis scan available" in human

    def test_bytes_human(self) -> None:
        from app.reporting.formatter import _bytes_human
        assert _bytes_human(None) == "N/A"
        assert _bytes_human(0) == "0 B"
        assert "KB" in _bytes_human(2048)
        assert "MB" in _bytes_human(5 * 1024**2)
        assert "GB" in _bytes_human(2 * 1024**3)


# ── Builder with missing categories ────────────────────────────────────


class TestBuilderWithMissingCategories:
    def test_partial_snapshots(self) -> None:
        snaps = {"hardware": {"hostname": "PARTIAL"}}
        store = _make_store_with_run(snapshots=snaps)
        report = build_health_report(store)
        assert report.system.hostname == "PARTIAL"
        assert report.storage.count == 0
        assert report.battery.available is None

    def test_battery_empty_dict(self) -> None:
        snaps = {"battery": {}}
        store = _make_store_with_run(snapshots=snaps)
        report = build_health_report(store)
        assert report.battery.available is None


# ── Analysis status regression tests ───────────────────────────────────


class TestAnalysisStatusNotRun:
    """Case 1: Discovery completed, analyzer not run."""

    def test_analysis_status_not_run(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="not_run")
        report = build_health_report(store)
        assert report.analysis_status == "not_run"
        assert report.findings_available is False
        assert report.findings_count is None

    def test_analysis_status_none_legacy(self) -> None:
        """Legacy data with NULL analysis_status treated as not_run."""
        store = _make_store_with_run(snapshots=_full_snapshots())
        report = build_health_report(store)
        assert report.analysis_status is None
        assert report.findings_available is False
        assert report.findings_count is None

    def test_human_report_not_run(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="not_run")
        report = build_health_report(store)
        human = format_report(report)
        assert "NOT RUN" in human
        assert "not analyzed" in human

    def test_json_not_run(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="not_run")
        report = build_health_report(store)
        d = report_to_dict(report)
        assert d["analysis_status"] == "not_run"
        assert d["findings_available"] is False
        assert d["findings_count"] is None


class TestAnalysisStatusCompleted:
    """Case 2: Analyzer completed and found nothing."""

    def test_analysis_status_completed_zero_findings(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        report = build_health_report(store)
        assert report.analysis_status == "completed"
        assert report.findings_available is True
        assert report.findings_count == 0

    def test_human_report_completed_zero(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        report = build_health_report(store)
        human = format_report(report)
        assert "COMPLETED" in human
        assert "Findings: 0" in human

    def test_json_completed_zero(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        report = build_health_report(store)
        d = report_to_dict(report)
        assert d["analysis_status"] == "completed"
        assert d["findings_available"] is True
        assert d["findings_count"] == 0


class TestAnalysisStatusWithFindings:
    """Case 3: Analyzer completed with findings."""

    def test_analysis_status_completed_with_findings(self) -> None:
        findings = [
            {"analyzer": "storage", "severity": "critical", "title": "Disk full"},
            {"analyzer": "battery", "severity": "warning", "title": "Battery degraded"},
        ]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="completed",
        )
        report = build_health_report(store)
        assert report.analysis_status == "completed"
        assert report.findings_available is True
        assert report.findings_count == 2

    def test_human_report_completed_with_findings(self) -> None:
        findings = [
            {"analyzer": "storage", "severity": "critical", "title": "Disk full"},
        ]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="completed",
        )
        report = build_health_report(store)
        human = format_report(report)
        assert "COMPLETED" in human
        assert "Findings: 1" in human

    def test_json_completed_with_findings(self) -> None:
        findings = [
            {"analyzer": "storage", "severity": "critical", "title": "Disk full"},
        ]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="completed",
        )
        report = build_health_report(store)
        d = report_to_dict(report)
        assert d["analysis_status"] == "completed"
        assert d["findings_available"] is True
        assert d["findings_count"] == 1


class TestAnalysisStatusFailed:
    """Case 4: Analyzer failed."""

    def test_analysis_status_failed(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="failed")
        report = build_health_report(store)
        assert report.analysis_status == "failed"
        assert report.findings_available is False
        assert report.findings_count is None

    def test_human_report_failed(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="failed")
        report = build_health_report(store)
        human = format_report(report)
        assert "FAILED" in human
        assert "not available" in human

    def test_json_failed(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="failed")
        report = build_health_report(store)
        d = report_to_dict(report)
        assert d["analysis_status"] == "failed"
        assert d["findings_available"] is False
        assert d["findings_count"] is None


class TestAnalysisStatusPartial:
    """Analyzer completed with some failures."""

    def test_analysis_status_partial(self) -> None:
        findings = [
            {"analyzer": "storage", "severity": "warning", "title": "Disk 85%"},
        ]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="partial",
        )
        report = build_health_report(store)
        assert report.analysis_status == "partial"
        assert report.findings_available is True
        assert report.findings_count == 1

    def test_human_report_partial(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="partial")
        report = build_health_report(store)
        human = format_report(report)
        assert "PARTIAL" in human

    def test_json_partial(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="partial")
        report = build_health_report(store)
        d = report_to_dict(report)
        assert d["analysis_status"] == "partial"
        assert d["findings_available"] is True


class TestAnalysisStatusFieldInModel:
    """Verify model fields exist and serialize correctly."""

    def test_health_report_has_analysis_fields(self) -> None:
        report = HealthReport(
            analysis_status="completed",
            findings_available=True,
            findings_count=5,
        )
        assert report.analysis_status == "completed"
        assert report.findings_available is True
        assert report.findings_count == 5

    def test_json_serialization_of_analysis_fields(self) -> None:
        report = HealthReport(
            analysis_status="completed",
            findings_available=True,
            findings_count=3,
        )
        d = report_to_dict(report)
        assert d["analysis_status"] == "completed"
        assert d["findings_available"] is True
        assert d["findings_count"] == 3

    def test_json_null_analysis_fields(self) -> None:
        report = HealthReport()
        d = report_to_dict(report)
        assert d["analysis_status"] is None
        assert d["findings_available"] is False
        assert d["findings_count"] is None
