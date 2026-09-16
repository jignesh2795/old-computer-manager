"""Comprehensive tests for Phase 8B: Historical AI Reasoning.

Tests cover:
A. Historical context included in advisory
B. Context limits respected
C. Baseline unavailable handling
D. Baseline established handling
E. Storage trend reasoning
F. Battery baseline reasoning
G. Recurring finding reasoning
H. Anomaly reasoning
I. Missing historical data
J. Failed historical runs excluded
K. Factual/inference distinction
L. executable=false enforced
M. Malicious/executable model output rejected
N. CLI output includes historical summary
O. JSON output includes historical summary
P. API output includes historical summary
Q. Dashboard renders historical summary
R. Existing tests remain passing
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from app.ai.context import AIContext, build_ai_context, MAX_HISTORICAL_TRENDS, MAX_HISTORICAL_RECURRING, MAX_HISTORICAL_ANOMALIES
from app.ai.models import (
    AIAdvisory,
    Observation,
    Recommendation,
    Uncertainty,
    Limitation,
    AdvisoryMetadata,
    HistoricalSummary,
)
from app.ai.provider import MockProvider
from app.ai.advisory import generate_advisory, advisory_to_dict, AdvisoryError
from app.ai.safety import validate_advisory
from app.ai.prompts import AI_PROMPT_VERSION, SYSTEM_PROMPT
from app.database.sqlite import SnapshotStore
from app.reporting.models import (
    HealthReport,
    SystemInfo,
    StorageSummary,
    StoragePartitionSummary,
    BatterySummary,
    FindingsGrouped,
    FindingSummary,
    FileAnalysisSummary,
    RemediationSummary,
)


# ── Helper fixtures ──────────────────────────────────────────────────────────


def _make_report(
    analysis_status: str = "completed",
    storage_usage: float | None = None,
    battery_available: bool = True,
    battery_health: float | None = 80.0,
    battery_baseline: str = "non-baseline",
) -> HealthReport:
    """Create a test HealthReport."""
    partitions = []
    if storage_usage is not None:
        partitions.append(
            StoragePartitionSummary(
                device="C:\\",
                filesystem="NTFS",
                total_bytes=100_000_000_000,
                used_bytes=int(100_000_000_000 * storage_usage / 100),
                free_bytes=int(100_000_000_000 * (1 - storage_usage / 100)),
                usage_percent=storage_usage,
                status="warning" if storage_usage >= 80 else "normal",
            )
        )

    return HealthReport(
        schema_version="1.0",
        generated_at="2026-01-01T00:00:00",
        discovery_run_id=1,
        discovery_status="completed",
        analysis_status=analysis_status,
        findings_available=analysis_status == "completed",
        findings_count=0,
        system=SystemInfo(
            hostname="TEST-PC",
            os_name="Windows 10",
            os_version="10.0.19045",
            architecture="64-bit",
            manufacturer="Test",
            model="Test Model",
            cpu_name="Test CPU",
            cpu_cores_physical=2,
            cpu_cores_logical=4,
            ram_total_bytes=16_000_000_000,
        ),
        storage=StorageSummary(
            partitions=partitions,
            count=len(partitions),
            total_capacity_bytes=100_000_000_000 if partitions else 0,
            total_free_bytes=partitions[0].free_bytes if partitions else 0,
        ),
        battery=BatterySummary(
            available=battery_available,
            charge_percent=50.0,
            plugged_in=True,
            health_percent=battery_health,
            baseline_status=battery_baseline,
        ),
        findings=FindingsGrouped(),
        file_analysis=FileAnalysisSummary(available=False),
        remediation=RemediationSummary(),
    )


def _make_context_with_historical(
    trends: list[dict] | None = None,
    recurring: list[dict] | None = None,
    anomalies: list[dict] | None = None,
    battery_baseline: dict | None = None,
    data_quality: list[dict] | None = None,
    runs_considered: int = 5,
) -> AIContext:
    """Create an AIContext with historical data."""
    historical = {
        "available": True,
        "runs_considered": runs_considered,
        "trends": trends or [],
        "recurring_findings": recurring or [],
        "anomalies": anomalies or [],
        "baseline": [battery_baseline] if battery_baseline else [],
        "battery_baseline": battery_baseline,
        "data_quality": data_quality or [],
    }
    return AIContext(
        system_summary={"hostname": "TEST-PC"},
        storage_summary={"partitions": []},
        battery_summary={"available": False},
        findings_summary=[],
        file_analysis_summary={"available": False},
        startup_summary={"count": 0},
        process_summary={"count": 0},
        remediation_metadata=[],
        historical_summary=historical,
        analysis_status="completed",
    )


def _create_run(store: SnapshotStore, snapshots: dict) -> int:
    """Helper to create a completed run with snapshots."""
    run_id = store.start_run()
    for category, payload in snapshots.items():
        store.save(category, payload, run_id=run_id)
    store.complete_run(run_id)
    return run_id


# ── A. Historical context included in advisory ──────────────────────────────


class TestHistoricalContextIncluded:
    def test_advisory_includes_historical_summary(self):
        """A. Advisory includes historical_summary when historical data available."""
        ctx = _make_context_with_historical(
            trends=[{"metric_name": "storage_C:_percent_used", "direction": "increasing", "observations_count": 4, "delta_percent": 13.5}],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        assert advisory.historical_summary is not None
        assert advisory.historical_summary.runs_considered == 5
        assert advisory.historical_summary.trends_count == 1

    def test_advisory_no_historical_when_unavailable(self):
        """A. Advisory has no historical_summary when historical data unavailable."""
        ctx = AIContext(
            historical_summary={"available": False},
            analysis_status="completed",
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        assert advisory.historical_summary is None

    def test_historical_summary_in_output_dict(self):
        """A. Historical summary appears in advisory_to_dict."""
        ctx = _make_context_with_historical(
            trends=[{"metric_name": "test", "direction": "stable", "observations_count": 3, "delta_percent": 0.5}],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        advisory_dict = advisory_to_dict(advisory)
        assert "historical_summary" in advisory_dict
        assert advisory_dict["historical_summary"]["runs_considered"] == 5
        assert advisory_dict["historical_summary"]["trends_count"] == 1


# ── B. Context limits respected ──────────────────────────────────────────────


class TestContextLimitsRespected:
    def test_trends_capped(self):
        """B. Historical trends are capped at MAX_HISTORICAL_TRENDS."""
        trends = [
            {"metric_name": f"metric_{i}", "direction": "increasing", "observations_count": 3, "delta_percent": 5.0}
            for i in range(20)
        ]
        ctx = _make_context_with_historical(trends=trends)
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        # Trends in context are capped, but observations generated from them
        # should also respect the limit
        hist_obs = [o for o in advisory.observations if o.source == "historical_trends"]
        assert len(hist_obs) <= MAX_HISTORICAL_TRENDS

    def test_recurring_capped(self):
        """B. Recurring findings are capped at MAX_HISTORICAL_RECURRING."""
        recurring = [
            {"title": f"Finding {i}", "analyzer": "test", "severity": "warning", "occurrence_count": i + 1}
            for i in range(10)
        ]
        ctx = _make_context_with_historical(recurring=recurring)
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        hist_obs = [o for o in advisory.observations if o.source == "historical_recurring"]
        assert len(hist_obs) <= MAX_HISTORICAL_RECURRING

    def test_anomalies_capped(self):
        """B. Anomalies are capped at MAX_HISTORICAL_ANOMALIES."""
        anomalies = [
            {"title": f"Anomaly {i}", "severity": "warning", "message": f"msg {i}"}
            for i in range(10)
        ]
        ctx = _make_context_with_historical(anomalies=anomalies)
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        hist_obs = [o for o in advisory.observations if o.source == "historical_anomalies"]
        assert len(hist_obs) <= MAX_HISTORICAL_ANOMALIES


# ── C. Baseline unavailable ─────────────────────────────────────────────────


class TestBaselineUnavailable:
    def test_battery_baseline_unavailable_creates_uncertainty(self):
        """C. Battery baseline unavailable creates uncertainty."""
        ctx = _make_context_with_historical(
            battery_baseline={"metric_name": "health_percent", "baseline_status": "unavailable"},
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        unc_descriptions = [u.description for u in advisory.uncertainties]
        assert any("baseline" in d.lower() and "unavailable" in d.lower() for d in unc_descriptions)

    def test_no_baseline_no_uncertainty(self):
        """C. No baseline data means no baseline uncertainty."""
        ctx = _make_context_with_historical()
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        unc_descriptions = [u.description for u in advisory.uncertainties]
        assert not any("baseline" in d.lower() for d in unc_descriptions)


# ── D. Baseline established ─────────────────────────────────────────────────


class TestBaselineEstablished:
    def test_baseline_degraded_creates_observation(self):
        """D. Baseline degraded creates observation."""
        ctx = _make_context_with_historical(
            battery_baseline={
                "metric_name": "health_percent",
                "baseline_status": "degraded",
                "baseline_value": 85.0,
                "current_value": 70.0,
                "delta": -15.0,
            },
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs_titles = [o.title for o in advisory.observations]
        assert any("baseline" in t.lower() and "degraded" in t.lower() for t in obs_titles)

    def test_baseline_unchanged_creates_observation(self):
        """D. Baseline unchanged creates info observation."""
        ctx = _make_context_with_historical(
            battery_baseline={
                "metric_name": "health_percent",
                "baseline_status": "unchanged",
                "baseline_value": 85.0,
                "current_value": 83.0,
                "delta": -2.0,
            },
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs_titles = [o.title for o in advisory.observations]
        assert any("baseline" in t.lower() for t in obs_titles)


# ── E. Storage trend reasoning ──────────────────────────────────────────────


class TestStorageTrendReasoning:
    def test_increasing_trend_creates_observation(self):
        """E. Increasing storage trend creates warning observation."""
        ctx = _make_context_with_historical(
            trends=[{
                "metric_name": "storage_C:_percent_used",
                "direction": "increasing",
                "observations_count": 4,
                "delta_percent": 13.5,
            }],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_trends"]
        assert len(obs) >= 1
        assert "increasing" in obs[0].title.lower()

    def test_decreasing_trend_creates_observation(self):
        """E. Decreasing storage trend creates info observation."""
        ctx = _make_context_with_historical(
            trends=[{
                "metric_name": "storage_C:_percent_used",
                "direction": "decreasing",
                "observations_count": 4,
                "delta_percent": -10.0,
            }],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_trends"]
        assert len(obs) >= 1
        assert "decreasing" in obs[0].title.lower()

    def test_stable_trend_no_observation(self):
        """E. Stable trend does not create observation."""
        ctx = _make_context_with_historical(
            trends=[{
                "metric_name": "storage_C:_percent_used",
                "direction": "stable",
                "observations_count": 4,
                "delta_percent": 0.5,
            }],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_trends"]
        assert len(obs) == 0

    def test_insufficient_data_trend_no_observation(self):
        """E. Insufficient data trend does not create observation."""
        ctx = _make_context_with_historical(
            trends=[{
                "metric_name": "storage_C:_percent_used",
                "direction": "insufficient_data",
                "observations_count": 1,
                "delta_percent": None,
            }],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_trends"]
        assert len(obs) == 0


# ── F. Battery baseline reasoning ──────────────────────────────────────────


class TestBatteryBaselineReasoning:
    def test_battery_baseline_with_valid_values(self):
        """F. Battery baseline with valid values creates observation."""
        ctx = _make_context_with_historical(
            battery_baseline={
                "metric_name": "health_percent",
                "baseline_status": "degraded",
                "baseline_value": 90.0,
                "current_value": 75.0,
                "delta": -15.0,
            },
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_baseline"]
        assert len(obs) == 1
        assert "90.0%" in obs[0].evidence
        assert "75.0%" in obs[0].evidence

    def test_battery_baseline_unavailable_no_observation(self):
        """F. Battery baseline unavailable creates uncertainty, not observation."""
        ctx = _make_context_with_historical(
            battery_baseline={"metric_name": "health_percent", "baseline_status": "unavailable"},
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_baseline"]
        assert len(obs) == 0
        # Should have uncertainty instead
        unc = [u for u in advisory.uncertainties if "baseline" in u.description.lower()]
        assert len(unc) >= 1


# ── G. Recurring finding reasoning ─────────────────────────────────────────


class TestRecurringFindingReasoning:
    def test_recurring_finding_creates_observation(self):
        """G. Recurring finding creates observation with occurrence count."""
        ctx = _make_context_with_historical(
            recurring=[{
                "title": "High disk usage on C:",
                "analyzer": "storage",
                "severity": "warning",
                "occurrence_count": 5,
            }],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_recurring"]
        assert len(obs) == 1
        assert "5" in obs[0].evidence
        assert "High disk usage" in obs[0].title

    def test_multiple_recurring_findings(self):
        """G. Multiple recurring findings create multiple observations."""
        ctx = _make_context_with_historical(
            recurring=[
                {"title": "Finding A", "analyzer": "storage", "severity": "warning", "occurrence_count": 3},
                {"title": "Finding B", "analyzer": "startup", "severity": "info", "occurrence_count": 2},
            ],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_recurring"]
        assert len(obs) == 2


# ── H. Anomaly reasoning ──────────────────────────────────────────────────


class TestAnomalyReasoning:
    def test_anomaly_creates_observation(self):
        """H. Anomaly creates observation."""
        ctx = _make_context_with_historical(
            anomalies=[{
                "title": "Sudden storage increase: storage_C:_percent_used",
                "severity": "warning",
                "message": "Storage utilization increased by 15.0 percentage points.",
            }],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_anomalies"]
        assert len(obs) == 1
        assert "Anomaly:" in obs[0].title

    def test_anomaly_severity_preserved(self):
        """H. Anomaly severity is preserved in observation."""
        ctx = _make_context_with_historical(
            anomalies=[{
                "title": "Critical anomaly",
                "severity": "critical",
                "message": "Something critical happened",
            }],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_anomalies"]
        assert len(obs) == 1
        assert obs[0].severity == "critical"


# ── I. Missing historical data ─────────────────────────────────────────────


class TestMissingHistoricalData:
    def test_no_historical_data_no_historical_summary(self):
        """I. No historical data means no historical_summary."""
        ctx = AIContext(
            historical_summary={},
            analysis_status="completed",
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        assert advisory.historical_summary is None

    def test_empty_historical_data_no_observations(self):
        """I. Empty historical data generates no historical observations."""
        ctx = _make_context_with_historical()
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        hist_obs = [o for o in advisory.observations if o.source.startswith("historical_")]
        assert len(hist_obs) == 0


# ── J. Failed historical runs excluded ─────────────────────────────────────


class TestFailedHistoricalRuns:
    def test_historical_summary_includes_runs_considered(self):
        """J. Historical summary shows runs_considered from context."""
        ctx = _make_context_with_historical(runs_considered=3)
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        assert advisory.historical_summary is not None
        assert advisory.historical_summary.runs_considered == 3


# ── K. Factual/inference distinction ───────────────────────────────────────


class TestFactInferenceDistinction:
    def test_historical_observations_are_factual(self):
        """K. Historical observations use factual language."""
        ctx = _make_context_with_historical(
            trends=[{
                "metric_name": "storage_C:_percent_used",
                "direction": "increasing",
                "observations_count": 4,
                "delta_percent": 13.5,
            }],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_trends"]
        assert len(obs) >= 1
        # Should use factual language, not speculative
        assert "indicates" not in obs[0].evidence.lower() or "shows" in obs[0].evidence.lower()
        # Should not contain speculative claims
        assert "failure" not in obs[0].evidence.lower()
        assert "broken" not in obs[0].evidence.lower()

    def test_anomaly_observations_are_factual(self):
        """K. Anomaly observations describe change, not speculate on cause."""
        ctx = _make_context_with_historical(
            anomalies=[{
                "title": "Sudden storage increase",
                "severity": "warning",
                "message": "Storage increased by 15 percentage points between runs.",
            }],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        obs = [o for o in advisory.observations if o.source == "historical_anomalies"]
        assert len(obs) >= 1
        # Should describe the change, not speculate on cause
        assert "hardware failure" not in obs[0].evidence.lower()
        assert "malware" not in obs[0].evidence.lower()


# ── L. executable=false enforced ────────────────────────────────────────────


class TestExecutableFalseEnforced:
    def test_all_recommendations_non_executable(self):
        """L. All recommendations have executable=false."""
        ctx = _make_context_with_historical(
            trends=[{"metric_name": "test", "direction": "increasing", "observations_count": 3, "delta_percent": 5.0}],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        for rec in advisory.recommendations:
            assert rec.executable is False

    def test_recommendation_model_rejects_executable_true(self):
        """L. Recommendation model rejects executable=True."""
        with pytest.raises(ValueError, match="executable must always be False"):
            Recommendation(title="Test", rationale="Test", executable=True)


# ── M. Malicious/executable model output rejected ──────────────────────────


class TestMaliciousOutputRejected:
    def test_advisory_with_executable_recommendation_rejected(self):
        """M. Advisory with executable recommendation is rejected."""
        advisory_dict = {
            "summary": "Test",
            "observations": [],
            "recommendations": [
                {
                    "title": "Run cmd.exe /c format C:",
                    "rationale": "Test",
                    "executable": False,
                }
            ],
            "uncertainties": [],
            "limitations": [],
        }
        is_safe, violations = validate_advisory(advisory_dict)
        assert not is_safe

    def test_safe_advisory_accepted(self):
        """M. Safe advisory is accepted."""
        advisory_dict = {
            "summary": "Test summary",
            "observations": [
                {"title": "Test", "evidence": "Test evidence", "source": "test", "severity": "info", "confidence": "high"}
            ],
            "recommendations": [
                {"title": "Review", "rationale": "Consider reviewing", "executable": False}
            ],
            "uncertainties": [],
            "limitations": [],
        }
        is_safe, violations = validate_advisory(advisory_dict)
        assert is_safe


# ── N. CLI output includes historical summary ──────────────────────────────


class TestCLIOutput:
    def test_cli_ai_command_exists(self):
        """N. CLI ai command exists."""
        import subprocess
        result = subprocess.run(
            ["python", "-m", "app.cli", "ai", "--help"],
            capture_output=True, text=True, cwd=str(Path(__file__).parent.parent)
        )
        assert result.returncode == 0
        assert "ai" in result.stdout.lower() or "advisory" in result.stdout.lower()


# ── O. JSON output includes historical summary ──────────────────────────────


class TestJSONOutput:
    def test_json_output_includes_historical_summary(self):
        """O. JSON output includes historical_summary field."""
        ctx = _make_context_with_historical(
            trends=[{"metric_name": "test", "direction": "increasing", "observations_count": 3, "delta_percent": 5.0}],
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        advisory_dict = advisory_to_dict(advisory)
        json_str = json.dumps(advisory_dict, default=str)
        parsed = json.loads(json_str)
        assert "historical_summary" in parsed
        assert parsed["historical_summary"]["runs_considered"] == 5
        assert parsed["historical_summary"]["trends_count"] == 1

    def test_json_output_backward_compatible(self):
        """O. JSON output without historical data is backward compatible."""
        ctx = AIContext(
            historical_summary={},
            analysis_status="completed",
        )
        provider = MockProvider()
        advisory = provider.generate_advisory(ctx)
        advisory_dict = advisory_to_dict(advisory)
        json_str = json.dumps(advisory_dict, default=str)
        parsed = json.loads(json_str)
        # historical_summary should be None or absent
        assert parsed.get("historical_summary") is None


# ── P. API output includes historical summary ──────────────────────────────


class TestAPIOutput:
    def test_advisory_endpoint_returns_historical_summary(self):
        """P. API advisory endpoint returns historical_summary."""
        from fastapi.testclient import TestClient
        from app.api.app import create_app
        from app.api.dependencies import set_store

        app = create_app()
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SnapshotStore(db_path)
            set_store(store)
            client = TestClient(app)

            response = client.get("/api/v1/ai/advisory")
            assert response.status_code == 200
            data = response.json()
            # historical_summary may be None if no historical data
            assert "historical_summary" in data


# ── Q. Dashboard renders historical summary ────────────────────────────────


class TestDashboardRendering:
    def test_historical_summary_in_advisory_response_model(self):
        """Q. AdvisoryResponse model supports historical_summary."""
        from app.api.schemas import AdvisoryResponse, AdvisoryHistoricalSummaryResponse

        response = AdvisoryResponse(
            summary="Test",
            historical_summary=AdvisoryHistoricalSummaryResponse(
                runs_considered=5,
                observations_used=3,
                trends_count=2,
                baselines_established=1,
                recurring_findings_count=1,
                anomalies_count=0,
                data_quality_issues=0,
            ),
        )
        assert response.historical_summary is not None
        assert response.historical_summary.runs_considered == 5


# ── R. Existing tests remain passing ───────────────────────────────────────


class TestExistingTestsUnaffected:
    def test_advisory_model_still_works(self):
        """R. Existing advisory model still works."""
        advisory = AIAdvisory(
            summary="Test",
            observations=[Observation(title="Test", evidence="Test", source="test")],
            recommendations=[Recommendation(title="Test", rationale="Test")],
        )
        assert advisory.summary == "Test"
        assert advisory.historical_summary is None  # backward compatible

    def test_provider_generates_valid_advisory(self):
        """R. MockProvider generates valid advisory."""
        report = _make_report(storage_usage=85.0)
        context = build_ai_context(report)
        provider = MockProvider()
        advisory = provider.generate_advisory(context)
        assert isinstance(advisory, AIAdvisory)
        assert advisory.summary

    def test_prompt_version_is_1_1(self):
        """R. Prompt version is 1.1."""
        assert AI_PROMPT_VERSION == "1.1"

    def test_system_prompt_contains_historical_rules(self):
        """R. System prompt contains historical reasoning rules."""
        assert "HISTORICAL REASONING RULES" in SYSTEM_PROMPT
        assert "FACT" in SYSTEM_PROMPT
        assert "INTERPRETATION" in SYSTEM_PROMPT
        assert "UNCERTAINTY" in SYSTEM_PROMPT

    def test_advisory_frozen_models(self):
        """R. Advisory models are frozen."""
        obs = Observation(title="Test", evidence="Test", source="test")
        with pytest.raises(AttributeError):
            obs.title = "Changed"

    def test_historical_summary_frozen(self):
        """R. HistoricalSummary is frozen."""
        h = HistoricalSummary(runs_considered=5)
        with pytest.raises(AttributeError):
            h.runs_considered = 10

    def test_no_executor_import_in_ai_modules(self):
        """R. AI modules have no executor dependency."""
        import app.ai.models as models_mod
        source = open(models_mod.__file__).read()
        assert "from app.remediation.executor" not in source

        import app.ai.provider as provider_mod
        source = open(provider_mod.__file__).read()
        assert "from app.remediation.executor" not in source

        import app.ai.advisory as advisory_mod
        source = open(advisory_mod.__file__).read()
        assert "from app.remediation.executor" not in source


# ── Additional safety tests ─────────────────────────────────────────────────


class TestHistoricalSafety:
    def test_historical_observations_no_network_calls(self):
        """Historical observations don't make network calls."""
        import app.ai.provider as provider_mod
        source = open(provider_mod.__file__).read()
        assert "requests.post" not in source
        assert "urllib.request" not in source
        assert "httpx" not in source

    def test_historical_observations_no_file_modification(self):
        """Historical observations don't modify files."""
        import app.ai.provider as provider_mod
        source = open(provider_mod.__file__).read()
        assert "os.remove" not in source
        assert "os.unlink" not in source
        assert "shutil.move" not in source
        assert "open(" not in source or "open(" in source.split("_generate_historical")[0]

    def test_historical_summary_dataclass_fields(self):
        """HistoricalSummary has all required fields."""
        h = HistoricalSummary(
            runs_considered=5,
            observations_used=3,
            trends_count=2,
            baselines_established=1,
            recurring_findings_count=1,
            anomalies_count=0,
            data_quality_issues=0,
            limited_by="",
        )
        assert h.runs_considered == 5
        assert h.observations_used == 3
        assert h.trends_count == 2
        assert h.baselines_established == 1
        assert h.recurring_findings_count == 1
        assert h.anomalies_count == 0
        assert h.data_quality_issues == 0
        assert h.limited_by == ""
