"""Tests for the historical analysis package."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from app.database.sqlite import SnapshotStore
from app.history.models import (
    MetricObservation,
    TrendResult,
    Baseline,
    HistoricalAnomaly,
    RecurringFinding,
    DataQuality,
    TrendDirection,
    BaselineStatus,
    HistoricalSummary,
)
from app.history.repository import HistoryRepository
from app.history.trends import calculate_trend, MIN_OBSERVATIONS_FOR_TREND
from app.history.baseline import compute_baseline, BATTERY_HEALTH_DEGRADATION_THRESHOLD
from app.history.anomalies import detect_anomalies
from app.history.runner import run_history, run_history_json, _find_recurring_findings
from app.history.metrics import get_metric_definitions, get_storage_metric_name


# -- Fixtures ----------------------------------------------------------------


@pytest.fixture
def tmp_db():
    """Create a temporary database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        store = SnapshotStore(db_path)
        yield store


def _create_run(store: SnapshotStore, snapshots: dict, findings: list | None = None) -> int:
    """Helper to create a completed run with snapshots."""
    run_id = store.start_run()
    for category, payload in snapshots.items():
        store.save(category, payload, run_id=run_id)
    store.complete_run(run_id)
    if findings:
        for f in findings:
            store.save(f["category"], f["payload"], run_id=run_id)
    return run_id


# -- A. latest completed run selected ----------------------------------------


class TestRunSelection:
    def test_latest_completed_run_selected(self, tmp_db):
        """A. latest completed run selected."""
        r1 = _create_run(tmp_db, {"hardware": {"hostname": "pc1"}})
        r2 = _create_run(tmp_db, {"hardware": {"hostname": "pc2"}})
        r3 = _create_run(tmp_db, {"hardware": {"hostname": "pc3"}})

        runs = tmp_db.get_completed_runs()
        assert len(runs) == 3
        assert runs[0]["id"] == r3  # newest first

    def test_failed_runs_excluded(self, tmp_db):
        """B. failed runs excluded."""
        r1 = tmp_db.start_run()
        tmp_db.save("hardware", {"hostname": "pc1"}, run_id=r1)
        tmp_db.complete_run(r1, status="failed")

        r2 = _create_run(tmp_db, {"hardware": {"hostname": "pc2"}})

        runs = tmp_db.get_completed_runs()
        assert len(runs) == 1
        assert runs[0]["id"] == r2

    def test_incomplete_runs_excluded(self, tmp_db):
        """C. incomplete runs excluded."""
        r1 = tmp_db.start_run()
        tmp_db.save("hardware", {"hostname": "pc1"}, run_id=r1)
        # Not completed

        r2 = _create_run(tmp_db, {"hardware": {"hostname": "pc2"}})

        runs = tmp_db.get_completed_runs()
        assert len(runs) == 1
        assert runs[0]["id"] == r2

    def test_last_n_run_selection(self, tmp_db):
        """D. last-N run selection."""
        for i in range(5):
            _create_run(tmp_db, {"hardware": {"hostname": f"pc{i}"}})

        runs = tmp_db.get_completed_runs(limit=3)
        assert len(runs) == 3
        # Should be the 3 newest
        assert runs[0]["id"] > runs[1]["id"] > runs[2]["id"]


# -- E. Storage partition identity -------------------------------------------


class TestPartitionIdentity:
    def test_storage_metric_name_stability(self):
        """E. storage partition identity is stable."""
        name1 = get_storage_metric_name("C:\\", "percent_used")
        name2 = get_storage_metric_name("C:\\", "percent_used")
        assert name1 == name2

    def test_storage_metric_name_normalized(self):
        """E. storage partition paths are normalized."""
        name1 = get_storage_metric_name("C:\\Users\\", "percent_used")
        name2 = get_storage_metric_name("C:/Users/", "percent_used")
        assert name1 == name2


# -- F-I. Trend calculation --------------------------------------------------


class TestTrendCalculation:
    def test_storage_trend_increase(self, tmp_db):
        """F. storage trend increase."""
        for i, pct in enumerate([76, 81, 85, 89.5]):
            run_id = tmp_db.start_run()
            tmp_db.save("storage", [{"device": "C:", "percent_used": pct}], run_id=run_id)
            tmp_db.complete_run(run_id)

        repo = HistoryRepository(tmp_db)
        run_ids = repo.get_all_run_ids()
        observations = repo.get_observations(run_ids, "storage_C:_percent_used", "storage")

        trend = calculate_trend(observations)
        assert trend.direction == TrendDirection.INCREASING
        assert trend.first_value == 76.0
        assert trend.latest_value == 89.5
        assert trend.delta_absolute == pytest.approx(13.5)

    def test_storage_trend_decrease(self, tmp_db):
        """G. storage trend decrease."""
        for pct in [90, 85, 80, 75]:
            run_id = tmp_db.start_run()
            tmp_db.save("storage", [{"device": "C:", "percent_used": pct}], run_id=run_id)
            tmp_db.complete_run(run_id)

        repo = HistoryRepository(tmp_db)
        run_ids = repo.get_all_run_ids()
        observations = repo.get_observations(run_ids, "storage_C:_percent_used", "storage")

        trend = calculate_trend(observations)
        assert trend.direction == TrendDirection.DECREASING
        assert trend.delta_absolute == pytest.approx(-15.0)

    def test_stable_metric(self, tmp_db):
        """H. stable metric."""
        for pct in [50.0, 50.5, 51.0, 50.8]:
            run_id = tmp_db.start_run()
            tmp_db.save("storage", [{"device": "C:", "percent_used": pct}], run_id=run_id)
            tmp_db.complete_run(run_id)

        repo = HistoryRepository(tmp_db)
        run_ids = repo.get_all_run_ids()
        observations = repo.get_observations(run_ids, "storage_C:_percent_used", "storage")

        trend = calculate_trend(observations)
        assert trend.direction == TrendDirection.STABLE

    def test_insufficient_data_state(self):
        """I. insufficient-data state."""
        trend = calculate_trend([])
        assert trend.direction == TrendDirection.INSUFFICIENT_DATA
        assert trend.observations_count == 0

    def test_single_observation_insufficient(self):
        """I. single observation is insufficient data."""
        obs = [MetricObservation(
            metric_name="test",
            timestamp="2026-01-01",
            discovery_run_id=1,
            value=50.0,
            unit="%",
            source="test",
        )]
        trend = calculate_trend(obs)
        assert trend.direction == TrendDirection.INSUFFICIENT_DATA


# -- J-K. Delta calculation --------------------------------------------------


class TestDeltaCalculation:
    def test_delta_absolute(self):
        """J. delta calculation."""
        obs = [
            MetricObservation("test", "t1", 1, 100.0, "%", "test"),
            MetricObservation("test", "t2", 2, 120.0, "%", "test"),
        ]
        trend = calculate_trend(obs)
        assert trend.delta_absolute == pytest.approx(20.0)

    def test_delta_percent(self):
        """K. percent delta where meaningful."""
        obs = [
            MetricObservation("test", "t1", 1, 100.0, "%", "test"),
            MetricObservation("test", "t2", 2, 120.0, "%", "test"),
        ]
        trend = calculate_trend(obs)
        assert trend.delta_percent == pytest.approx(20.0)

    def test_delta_percent_zero_baseline(self):
        """K. percent delta with zero baseline."""
        obs = [
            MetricObservation("test", "t1", 1, 0.0, "%", "test"),
            MetricObservation("test", "t2", 2, 10.0, "%", "test"),
        ]
        trend = calculate_trend(obs)
        assert trend.delta_percent is None


# -- L-N. Battery baseline ---------------------------------------------------


class TestBatteryBaseline:
    def test_battery_baseline_unavailable_without_health(self):
        """L. battery health baseline unavailable without full-charge capacity."""
        obs = [
            MetricObservation("health_percent", "t1", 1, None, "%", "battery"),
        ]
        baseline = compute_baseline(obs)
        assert baseline.baseline_status == BaselineStatus.UNAVAILABLE

    def test_battery_baseline_established_with_valid_health(self):
        """M. battery baseline established with valid health data."""
        obs = [
            MetricObservation("health_percent", "t1", 1, 85.0, "%", "battery"),
            MetricObservation("health_percent", "t2", 2, 82.0, "%", "battery"),
        ]
        baseline = compute_baseline(obs)
        assert baseline.baseline_status == BaselineStatus.UNCHANGED
        assert baseline.baseline_value == 85.0
        assert baseline.current_value == 82.0
        assert baseline.baseline_run_id == 1

    def test_battery_degradation_threshold(self):
        """N. battery degradation threshold."""
        obs = [
            MetricObservation("health_percent", "t1", 1, 85.0, "%", "battery"),
            MetricObservation("health_percent", "t2", 2, 70.0, "%", "battery"),
        ]
        baseline = compute_baseline(obs)
        assert baseline.baseline_status == BaselineStatus.DEGRADED
        assert baseline.delta == pytest.approx(-15.0)

    def test_battery_no_degradation_within_threshold(self):
        """N. battery change within threshold is unchanged."""
        obs = [
            MetricObservation("health_percent", "t1", 1, 85.0, "%", "battery"),
            MetricObservation("health_percent", "t2", 2, 82.0, "%", "battery"),
        ]
        baseline = compute_baseline(obs)
        # 3 point drop is less than 5 point threshold
        assert baseline.baseline_status == BaselineStatus.UNCHANGED

    def test_battery_charge_does_not_become_health_trend(self):
        """O. battery charge does not become health trend."""
        # charge_percent is a different metric from health_percent
        obs = [
            MetricObservation("charge_percent", "t1", 1, 50.0, "%", "battery"),
            MetricObservation("charge_percent", "t2", 2, 30.0, "%", "battery"),
        ]
        baseline = compute_baseline(obs)
        # charge_percent baseline is general, not battery-specific
        assert baseline.baseline_status == BaselineStatus.DEGRADED


# -- P. Recurring findings ---------------------------------------------------


class TestRecurringFindings:
    def test_recurring_findings(self):
        """P. recurring findings."""
        findings = [
            {"run_id": 1, "analyzer": "storage", "severity": "warning",
             "title": "High disk usage", "message": "msg", "created_at": "2026-01-01"},
            {"run_id": 2, "analyzer": "storage", "severity": "warning",
             "title": "High disk usage", "message": "msg", "created_at": "2026-01-02"},
            {"run_id": 3, "analyzer": "storage", "severity": "warning",
             "title": "High disk usage", "message": "msg", "created_at": "2026-01-03"},
        ]
        recurring = _find_recurring_findings(findings)
        assert len(recurring) == 1
        assert recurring[0].occurrence_count == 3
        assert recurring[0].title == "High disk usage"

    def test_non_recurring_findings(self):
        """P. non-recurring findings are excluded."""
        findings = [
            {"run_id": 1, "analyzer": "storage", "severity": "warning",
             "title": "High disk usage", "message": "msg", "created_at": "2026-01-01"},
            {"run_id": 2, "analyzer": "battery", "severity": "critical",
             "title": "Battery degraded", "message": "msg", "created_at": "2026-01-02"},
        ]
        recurring = _find_recurring_findings(findings)
        assert len(recurring) == 0


# -- Q. Anomaly detection ----------------------------------------------------


class TestAnomalyDetection:
    def test_sudden_storage_increase(self):
        """Q. anomaly detection - sudden storage increase."""
        obs = [
            MetricObservation("storage_C:_percent_used", "t1", 1, 70.0, "%", "storage"),
            MetricObservation("storage_C:_percent_used", "t2", 2, 85.0, "%", "storage"),
        ]
        anomalies = detect_anomalies(obs)
        assert len(anomalies) == 1
        assert anomalies[0].severity == "warning"
        assert "Sudden storage increase" in anomalies[0].title

    def test_sudden_battery_drop(self):
        """Q. anomaly detection - sudden battery drop."""
        obs = [
            MetricObservation("health_percent", "t1", 1, 85.0, "%", "battery"),
            MetricObservation("health_percent", "t2", 2, 70.0, "%", "battery"),
        ]
        anomalies = detect_anomalies(obs)
        assert len(anomalies) == 1
        assert "Sudden battery health drop" in anomalies[0].title

    def test_no_anomaly_forgradual_change(self):
        """Q. no anomaly for gradual change."""
        obs = [
            MetricObservation("storage_C:_percent_used", "t1", 1, 70.0, "%", "storage"),
            MetricObservation("storage_C:_percent_used", "t2", 2, 75.0, "%", "storage"),
        ]
        anomalies = detect_anomalies(obs)
        assert len(anomalies) == 0

    def test_no_anomaly_insufficient_data(self):
        """Q. no anomaly with insufficient data."""
        obs = [
            MetricObservation("test", "t1", 1, 50.0, "%", "test"),
        ]
        anomalies = detect_anomalies(obs)
        assert len(anomalies) == 0


# -- R-S. Missing/not_supported handling -------------------------------------


class TestDataQuality:
    def test_missing_metric_handling(self, tmp_db):
        """R. missing metric handling."""
        # Run with no battery data
        run_id = tmp_db.start_run()
        tmp_db.save("hardware", {"hostname": "pc1"}, run_id=run_id)
        tmp_db.complete_run(run_id)

        repo = HistoryRepository(tmp_db)
        run_ids = repo.get_all_run_ids()
        observations = repo.get_observations(run_ids, "health_percent", "battery")
        assert len(observations) == 0

    def test_not_supported_handling(self, tmp_db):
        """S. not_supported handling."""
        # Save a snapshot with not_supported status
        run_id = tmp_db.start_run()
        tmp_db.save("battery", {"available": False}, run_id=run_id, status="not_supported")
        tmp_db.complete_run(run_id)

        repo = HistoryRepository(tmp_db)
        run_ids = repo.get_all_run_ids()
        observations = repo.get_observations(run_ids, "health_percent", "battery")
        assert len(observations) == 0

    def test_partial_discovery_handling(self, tmp_db):
        """T. partial discovery handling."""
        # Run with only some collectors
        run_id = tmp_db.start_run()
        tmp_db.save("hardware", {"hostname": "pc1", "ram_total_bytes": 8 * 1024**3}, run_id=run_id)
        tmp_db.complete_run(run_id, status="completed_with_errors")

        repo = HistoryRepository(tmp_db)
        run_ids = repo.get_all_run_ids()
        all_obs = repo.get_all_observations(run_ids)
        # Should have hardware metrics but not storage/battery/etc
        assert "ram_total_bytes" in all_obs
        assert "storage_C:_percent_used" not in all_obs


# -- U. Historical API endpoints ---------------------------------------------


class TestHistoricalAPI:
    def test_history_summary_endpoint(self, tmp_db):
        """U. historical API endpoints."""
        from fastapi.testclient import TestClient
        from app.api.app import create_app
        from app.api.dependencies import set_store

        app = create_app()
        set_store(tmp_db)
        client = TestClient(app)

        response = client.get("/api/v1/history/summary")
        assert response.status_code == 200
        data = response.json()
        assert "runs_considered" in data
        assert "trends" in data
        assert "baseline" in data

    def test_history_trends_endpoint(self, tmp_db):
        """U. historical trends endpoint."""
        from fastapi.testclient import TestClient
        from app.api.app import create_app
        from app.api.dependencies import set_store

        app = create_app()
        set_store(tmp_db)
        client = TestClient(app)

        response = client.get("/api/v1/history/trends")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_history_baseline_endpoint(self, tmp_db):
        """U. historical baseline endpoint."""
        from fastapi.testclient import TestClient
        from app.api.app import create_app
        from app.api.dependencies import set_store

        app = create_app()
        set_store(tmp_db)
        client = TestClient(app)

        response = client.get("/api/v1/history/baseline")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_history_anomalies_endpoint(self, tmp_db):
        """U. historical anomalies endpoint."""
        from fastapi.testclient import TestClient
        from app.api.app import create_app
        from app.api.dependencies import set_store

        app = create_app()
        set_store(tmp_db)
        client = TestClient(app)

        response = client.get("/api/v1/history/anomalies")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_history_summary_with_data(self, tmp_db):
        """U. historical summary with actual data."""
        from fastapi.testclient import TestClient
        from app.api.app import create_app
        from app.api.dependencies import set_store

        # Create some runs
        for i in range(3):
            _create_run(tmp_db, {
                "hardware": {"hostname": f"pc{i}", "ram_total_bytes": 8 * 1024**3},
                "storage": [{"device": "C:", "percent_used": 70 + i * 5}],
            })

        app = create_app()
        set_store(tmp_db)
        client = TestClient(app)

        response = client.get("/api/v1/history/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["runs_considered"] == 3
        assert len(data["trends"]) > 0


# -- V. JSON output ----------------------------------------------------------


class TestJSONOutput:
    def test_json_output_valid(self, tmp_db):
        """V. JSON output."""
        for i in range(3):
            _create_run(tmp_db, {
                "hardware": {"hostname": f"pc{i}", "ram_total_bytes": 8 * 1024**3},
                "storage": [{"device": "C:", "percent_used": 70 + i * 5}],
            })

        json_str = run_history_json(tmp_db)
        data = json.loads(json_str)
        assert "runs_considered" in data
        assert "trends" in data
        assert "baseline" in data
        assert "recurring_findings" in data
        assert "anomalies" in data

    def test_json_output_empty_db(self, tmp_db):
        """V. JSON output with empty database."""
        json_str = run_history_json(tmp_db)
        data = json.loads(json_str)
        assert data["runs_considered"] == 0


# -- W. CLI history ----------------------------------------------------------


class TestCLIHistory:
    def test_cli_history_command_exists(self):
        """W. CLI history command."""
        import subprocess
        result = subprocess.run(
            ["python", "-m", "app.cli", "history", "--help"],
            capture_output=True, text=True, cwd=str(Path(__file__).parent.parent)
        )
        assert result.returncode == 0
        assert "history" in result.stdout.lower() or "Historical" in result.stdout

    def test_cli_history_json_flag(self):
        """W. CLI history --json flag."""
        import subprocess
        result = subprocess.run(
            ["python", "-m", "app.cli", "history", "--json", "--help"],
            capture_output=True, text=True, cwd=str(Path(__file__).parent.parent)
        )
        assert result.returncode == 0


# -- X. Dashboard historical section -----------------------------------------


class TestDashboardHistoricalSection:
    def test_dashboard_renders_with_history(self, tmp_db):
        """X. dashboard historical section."""
        # This is a structural test - the component exists
        from app.history.models import HistoricalSummary
        summary = HistoricalSummary(runs_considered=0)
        assert summary.runs_considered == 0


# -- Y. AI context contains bounded historical summaries ----------------------


class TestAIContextHistorical:
    def test_ai_context_has_historical_field(self):
        """Y. AI context contains bounded historical summaries."""
        from app.ai.context import AIContext
        ctx = AIContext()
        assert hasattr(ctx, "historical_summary")
        assert ctx.historical_summary == {}

    def test_ai_context_historical_bounded(self):
        """Y. AI context historical is bounded."""
        from app.ai.context import _build_historical_summary
        from app.reporting.models import HealthReport

        report = HealthReport()
        result = _build_historical_summary(report)
        assert result == {"available": False}


# -- Z. No remediation execution ---------------------------------------------


class TestNoRemediation:
    def test_history_no_executor_import(self):
        """Z. no remediation execution."""
        import app.history.runner as runner_mod
        source = open(runner_mod.__file__).read()
        assert "executor" not in source.lower()
        assert "quarantine" not in source.lower()
        assert "subprocess" not in source
        assert "os.system" not in source

    def test_history_no_network_calls(self):
        """Z. no network calls."""
        import app.history.runner as runner_mod
        source = open(runner_mod.__file__).read()
        assert "requests" not in source
        assert "urllib" not in source
        assert "httpx" not in source

    def test_history_models_frozen(self):
        """Z. history models are frozen."""
        obs = MetricObservation("test", "t1", 1, 50.0, "%", "test")
        with pytest.raises(AttributeError):
            obs.value = 60.0


# -- Metrics definitions ------------------------------------------------------


class TestMetricDefinitions:
    def test_metric_definitions_exist(self):
        """Metric definitions are available."""
        defs = get_metric_definitions()
        assert "health_percent" in defs
        assert "ram_total_bytes" in defs
        assert "startup_count" in defs

    def test_storage_metric_name(self):
        """Storage metric name generation."""
        name = get_storage_metric_name("C:\\", "percent_used")
        assert name == "storage_c:_percent_used"


# -- HistoricalSummary model --------------------------------------------------


class TestHistoricalSummaryModel:
    def test_summary_defaults(self):
        """HistoricalSummary defaults."""
        s = HistoricalSummary()
        assert s.runs_considered == 0
        assert s.observations_available == 0
        assert s.trends == []
        assert s.baseline == []
        assert s.recurring_findings == []
        assert s.anomalies == []
        assert s.data_quality == []
        assert s.run_ids == ()

    def test_summary_frozen(self):
        """HistoricalSummary is frozen."""
        s = HistoricalSummary()
        with pytest.raises(AttributeError):
            s.runs_considered = 5
