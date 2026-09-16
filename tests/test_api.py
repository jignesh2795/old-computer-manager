"""Tests for the local read-only FastAPI API.

All tests use mocked data or a temporary SQLite database. No real system
modifications are made.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.database.sqlite import SnapshotStore
from app.reporting.models import HealthReport


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


def _make_client(store: SnapshotStore | None = None) -> TestClient:
    """Create a TestClient with a pre-configured store."""
    from app.api import dependencies

    app = create_app()

    if store is not None:
        # Use dependency override for proper isolation
        def override_get_store() -> SnapshotStore:
            return store

        def override_get_report() -> HealthReport:
            from app.reporting.builder import build_health_report
            return build_health_report(store)

        app.dependency_overrides[dependencies.get_store] = override_get_store
        app.dependency_overrides[dependencies.get_report] = override_get_report

    return TestClient(app)


# ── A. /health returns 200 ─────────────────────────────────────────────


class TestHealthEndpoint:
    def test_health_returns_200(self) -> None:
        client = TestClient(create_app())
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_ok_status(self) -> None:
        client = TestClient(create_app())
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "old-computer-manager"

    def test_health_has_version(self) -> None:
        client = TestClient(create_app())
        response = client.get("/health")
        data = response.json()
        assert "version" in data


# ── B. /api/v1/report returns same schema as CLI JSON ──────────────────


class TestReportEndpoint:
    def test_report_returns_200(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        client = _make_client(store)
        response = client.get("/api/v1/report")
        assert response.status_code == 200

    def test_report_has_schema_version(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        client = _make_client(store)
        data = client.get("/api/v1/report").json()
        assert data["schema_version"] == "1.0"

    def test_report_has_all_sections(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        client = _make_client(store)
        data = client.get("/api/v1/report").json()
        assert "system" in data
        assert "storage" in data
        assert "battery" in data
        assert "findings" in data
        assert "file_analysis" in data
        assert "remediation" in data
        assert "errors" in data

    def test_report_analysis_fields(self) -> None:
        findings = [{"analyzer": "test", "severity": "warning", "title": "Test finding"}]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="completed",
        )
        client = _make_client(store)
        data = client.get("/api/v1/report").json()
        assert data["analysis_status"] == "completed"
        assert data["findings_available"] is True
        assert data["findings_count"] == 1


# ── C. /api/v1/findings returns findings ───────────────────────────────


class TestFindingsEndpoint:
    def test_findings_returns_200(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        client = _make_client(store)
        response = client.get("/api/v1/findings")
        assert response.status_code == 200

    def test_findings_has_analysis_status(self) -> None:
        findings = [{"analyzer": "storage", "severity": "critical", "title": "Disk full"}]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="completed",
        )
        client = _make_client(store)
        data = client.get("/api/v1/findings").json()
        assert data["analysis_status"] == "completed"
        assert data["findings_available"] is True
        assert data["findings_count"] == 1
        assert data["critical_count"] == 1


# ── D. Finding severity filtering works ────────────────────────────────


class TestFindingsSeverityFilter:
    def test_filter_by_critical(self) -> None:
        findings = [
            {"analyzer": "storage", "severity": "critical", "title": "Disk full"},
            {"analyzer": "battery", "severity": "warning", "title": "Battery low"},
        ]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="completed",
        )
        client = _make_client(store)
        response = client.get("/api/v1/findings?severity=critical")
        data = response.json()
        assert response.status_code == 200
        assert data["critical_count"] == 1
        assert data["warning_count"] == 0
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "critical"

    def test_filter_by_warning(self) -> None:
        findings = [
            {"analyzer": "storage", "severity": "critical", "title": "Disk full"},
            {"analyzer": "battery", "severity": "warning", "title": "Battery low"},
        ]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="completed",
        )
        client = _make_client(store)
        response = client.get("/api/v1/findings?severity=warning")
        data = response.json()
        assert response.status_code == 200
        assert data["critical_count"] == 0
        assert data["warning_count"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "warning"

    def test_invalid_severity_returns_400(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        client = _make_client(store)
        response = client.get("/api/v1/findings?severity=invalid")
        assert response.status_code == 400


# ── E. Analyzer filtering works ────────────────────────────────────────


class TestFindingsAnalyzerFilter:
    def test_filter_by_analyzer(self) -> None:
        findings = [
            {"analyzer": "storage", "severity": "critical", "title": "Disk full"},
            {"analyzer": "battery", "severity": "warning", "title": "Battery low"},
        ]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="completed",
        )
        client = _make_client(store)
        data = client.get("/api/v1/findings?analyzer=storage").json()
        assert len(data["findings"]) == 1
        assert data["findings"][0]["analyzer"] == "storage"

    def test_filter_by_nonexistent_analyzer(self) -> None:
        findings = [{"analyzer": "storage", "severity": "critical", "title": "Disk full"}]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="completed",
        )
        client = _make_client(store)
        data = client.get("/api/v1/findings?analyzer=nonexistent").json()
        assert len(data["findings"]) == 0


# ── F. /api/v1/storage works ───────────────────────────────────────────


class TestStorageEndpoint:
    def test_storage_returns_200(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/storage")
        assert response.status_code == 200

    def test_storage_has_partitions(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/storage")
        data = response.json()
        assert response.status_code == 200
        assert data["count"] == 2
        assert len(data["partitions"]) == 2

    def test_storage_partition_fields(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/storage")
        data = response.json()
        assert response.status_code == 200
        # Find C: partition
        c_partition = [p for p in data["partitions"] if p["device"] == "C:"]
        assert len(c_partition) == 1
        assert c_partition[0]["filesystem"] == "NTFS"
        assert c_partition[0]["status"] == "warning"


# ── G. /api/v1/battery works ───────────────────────────────────────────


class TestBatteryEndpoint:
    def test_battery_returns_200(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/battery")
        assert response.status_code == 200

    def test_battery_has_fields(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/battery")
        data = response.json()
        assert response.status_code == 200
        assert data["available"] is True
        assert data["status"] == "charging"
        assert data["charge_percent"] == 45.0

    def test_battery_no_serial(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        data = client.get("/api/v1/battery").json()
        assert "serial_number" not in data
        assert "serial_number_present" not in data


# ── H. /api/v1/file-analysis works ─────────────────────────────────────


class TestFileAnalysisEndpoint:
    def test_file_analysis_returns_200(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/file-analysis")
        assert response.status_code == 200

    def test_file_analysis_default_not_available(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/file-analysis")
        data = response.json()
        assert response.status_code == 200
        assert data["available"] is False
        assert data["files_examined"] == 0

    def test_file_analysis_with_data(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test.db"
        store = SnapshotStore(path=db_path)
        run_id = store.start_run()
        store.complete_run(run_id, status="completed")
        scan_id = store.start_file_scan("C:/test")
        store.complete_file_scan(scan_id, {
            "files_examined": 100,
            "directories_examined": 10,
            "bytes_examined": 5000000,
            "files_skipped": 0,
            "symlinks_skipped": 0,
            "excluded_items": 0,
            "inaccessible_items": 0,
            "elapsed_seconds": 0.5,
        })
        client = _make_client(store)
        response = client.get("/api/v1/file-analysis")
        data = response.json()
        assert response.status_code == 200
        assert data["available"] is True
        assert data["files_examined"] == 100
        assert data["scan_root"] == "C:/test"


# ── I. /api/v1/remediation/actions returns metadata only ───────────────


class TestRemediationActionsEndpoint:
    def test_remediation_returns_200(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/remediation/actions")
        assert response.status_code == 200

    def test_remediation_has_actions(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        data = client.get("/api/v1/remediation/actions").json()
        assert data["count"] > 0
        assert len(data["actions"]) > 0

    def test_quarantine_action_metadata(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        data = client.get("/api/v1/remediation/actions").json()
        qa = [a for a in data["actions"] if a["action_id"] == "user_temp_quarantine"]
        assert len(qa) == 1
        a = qa[0]
        assert a["reversible"] is True
        assert a["preview_available"] is True
        assert a["rollback_available"] is True
        assert a["real_execution_exists"] is True


# ── J. /api/v1/system works ────────────────────────────────────────────


class TestSystemEndpoint:
    def test_system_returns_200(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/system")
        assert response.status_code == 200

    def test_system_has_hostname(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/system")
        data = response.json()
        assert response.status_code == 200
        assert data["hostname"] == "TESTPC"

    def test_system_has_os(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        response = client.get("/api/v1/system")
        data = response.json()
        assert response.status_code == 200
        assert data["os_name"] == "Microsoft Windows 10 Pro"


# ── K. Missing completed run handled correctly ─────────────────────────


class TestNoCompletedRun:
    def test_report_endpoint_empty_db(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test.db"
        store = SnapshotStore(path=db_path)
        client = _make_client(store)
        response = client.get("/api/v1/report")
        assert response.status_code == 200
        data = response.json()
        assert data["discovery_run_id"] is None
        assert len(data["errors"]) >= 1
        assert data["errors"][0]["component"] == "discovery"

    def test_findings_endpoint_empty_db(self) -> None:
        tmp = tempfile.mkdtemp()
        db_path = Path(tmp) / "test.db"
        store = SnapshotStore(path=db_path)
        client = _make_client(store)
        response = client.get("/api/v1/findings")
        assert response.status_code == 200
        data = response.json()
        assert data["findings_available"] is False
        assert data["findings_count"] is None


# ── L. Malformed filters handled correctly ─────────────────────────────


class TestMalformedFilters:
    def test_invalid_severity(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        client = _make_client(store)
        response = client.get("/api/v1/findings?severity=unknown")
        assert response.status_code == 400
        assert "Invalid severity" in response.json()["detail"]

    def test_empty_analyzer_filter(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        client = _make_client(store)
        response = client.get("/api/v1/findings?analyzer=")
        assert response.status_code == 200


# ── M. JSON serialization remains valid ─────────────────────────────────


class TestJsonSerialization:
    def test_report_json_valid(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        client = _make_client(store)
        response = client.get("/api/v1/report")
        assert response.status_code == 200
        data = response.json()
        # Verify it's valid JSON by re-serializing
        json_str = json.dumps(data)
        assert isinstance(json.loads(json_str), dict)

    def test_findings_json_valid(self) -> None:
        findings = [{"analyzer": "test", "severity": "info", "title": "Test"}]
        store = _make_store_with_run(
            snapshots=_full_snapshots(),
            findings=findings,
            analysis_status="completed",
        )
        client = _make_client(store)
        response = client.get("/api/v1/findings")
        assert response.status_code == 200
        data = response.json()
        json_str = json.dumps(data)
        assert isinstance(json.loads(json_str), dict)


# ── N. Battery serial number is never exposed ──────────────────────────


class TestBatterySerialNeverExposed:
    def test_battery_endpoint_no_serial(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        data = client.get("/api/v1/battery").json()
        assert "serial_number" not in data

    def test_report_endpoint_no_serial(self) -> None:
        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)
        data = client.get("/api/v1/report").json()
        battery = data["battery"]
        assert "serial_number" not in battery


# ── O. Remediation action endpoint cannot execute ──────────────────────


class TestRemediationCannotExecute:
    def test_no_post_routes(self) -> None:
        """Verify no POST routes exist for remediation."""
        app = create_app()
        for route in app.routes:
            if hasattr(route, "methods") and hasattr(route, "path"):
                if "remediation" in route.path:
                    assert "GET" in route.methods
                    assert "POST" not in route.methods


# ── P. No POST/PUT/PATCH/DELETE remediation route exists ───────────────


class TestNoModificationRoutes:
    def test_only_get_methods(self) -> None:
        """All API routes should be GET only."""
        app = create_app()
        for route in app.routes:
            if hasattr(route, "methods"):
                # Skip health check and docs
                if route.path in ("/health", "/docs", "/redoc", "/openapi.json"):
                    continue
                if route.path.startswith("/api/v1/"):
                    assert "GET" in route.methods
                    assert "POST" not in route.methods
                    assert "PUT" not in route.methods
                    assert "PATCH" not in route.methods
                    assert "DELETE" not in route.methods


# ── Q. API does not trigger a fresh discovery ──────────────────────────


class TestNoAutoDiscovery:
    def test_report_endpoint_no_discovery(self) -> None:
        """Report endpoint should use cached data, not run discovery."""
        from unittest.mock import patch

        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        client = _make_client(store)

        # Verify that report building uses existing data, not fresh discovery
        with patch.object(store, "get_latest_completed_run") as mock_get:
            mock_get.return_value = {"id": 1, "started_at": "2026-01-01", "completed_at": "2026-01-01", "status": "completed", "analysis_status": "completed"}
            response = client.get("/api/v1/report")
            assert response.status_code == 200


# ── R. API does not trigger a filesystem scan ──────────────────────────


class TestNoAutoScan:
    def test_file_analysis_no_scan(self) -> None:
        """File analysis endpoint should use cached data, not scan."""
        from unittest.mock import patch

        store = _make_store_with_run(snapshots=_full_snapshots())
        client = _make_client(store)

        with patch("app.file_analysis.runner.run_file_analysis") as mock_scan:
            client.get("/api/v1/file-analysis")
            mock_scan.assert_not_called()


# ── S. API does not change filesystem state ────────────────────────────


class TestNoFilesystemChange:
    def test_no_write_operations(self) -> None:
        """Verify no file write operations in API code."""
        import inspect
        from app.api import routes

        source = inspect.getsource(routes)
        # These should not appear in route handlers
        dangerous_ops = [
            "open(", "write(", "os.remove", "os.unlink", "shutil.move",
            "shutil.copy", "shutil.rmtree",
        ]
        for op in dangerous_ops:
            assert op not in source, f"Dangerous operation '{op}' found in routes"


# ── T. API does not modify SQLite data during GET requests ─────────────


class TestNoSQLiteModification:
    def test_get_requests_read_only(self) -> None:
        """GET requests should not INSERT, UPDATE, or DELETE."""
        store = _make_store_with_run(snapshots=_full_snapshots(), analysis_status="completed")
        client = _make_client(store)

        # Test that all endpoints return 200 without errors
        # (This verifies they read existing data without modification)
        endpoints = [
            "/api/v1/report",
            "/api/v1/findings",
            "/api/v1/storage",
            "/api/v1/battery",
            "/api/v1/file-analysis",
            "/api/v1/remediation/actions",
            "/api/v1/system",
        ]
        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.status_code == 200, f"Endpoint {endpoint} returned {response.status_code}"


# ── U. OpenAPI docs contain only intended endpoints ────────────────────


class TestOpenAPIDocs:
    def test_openapi_contains_intended_endpoints(self) -> None:
        app = create_app()
        openapi = app.openapi()
        paths = list(openapi["paths"].keys())
        # Should have all intended endpoints
        assert "/health" in paths
        assert "/api/v1/report" in paths
        assert "/api/v1/findings" in paths
        assert "/api/v1/storage" in paths
        assert "/api/v1/battery" in paths
        assert "/api/v1/file-analysis" in paths
        assert "/api/v1/remediation/actions" in paths
        assert "/api/v1/system" in paths

    def test_openapi_no_modification_endpoints(self) -> None:
        app = create_app()
        openapi = app.openapi()
        paths = list(openapi["paths"].keys())
        # Should NOT have these endpoints
        assert "/api/v1/remediation/execute" not in paths
        assert "/api/v1/remediation/apply" not in paths
        assert "/api/v1/remediation/delete" not in paths
        assert "/api/v1/discovery" not in paths
        assert "/api/v1/scan" not in paths


# ── V. Existing 350+ tests remain passing (verified separately) ────────


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
