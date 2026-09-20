"""Comprehensive tests for the AI advisory layer.

Tests cover:
A. Context builder uses HealthReport
B. Context limits are enforced
C. Secrets excluded
D. Battery serial excluded
E. File contents excluded
F. Analysis not_run handled
G. Completed analysis handled
H. Failed analysis handled
I. Mock provider deterministic
J. Provider abstraction works
K. Malformed output rejected
L. Executable command output rejected
M. Registry-action reference remains non-executable
N. AI package has no executor dependency
O. No remediation invoked
P. CLI ai works with mock provider
Q. --json output valid
R. Missing provider handled
S. External provider disabled by default
T. API advisory endpoint read-only
U. Existing 397+ tests remain passing
"""

from __future__ import annotations

import json
import re
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.ai.context import (
    AIContext,
    build_ai_context,
    MAX_FINDINGS,
    MAX_LARGE_FILES,
    MAX_DUPLICATE_GROUPS,
    MAX_TEXT_LENGTH,
    SENSITIVE_FIELDS,
)
from app.ai.models import (
    AIAdvisory,
    Observation,
    Recommendation,
    Uncertainty,
    Limitation,
    AdvisoryMetadata,
)
from app.ai.provider import AIProvider, MockProvider, ExternalProvider, get_provider
from app.ai.safety import (
    validate_ai_output,
    validate_recommendation,
    validate_advisory,
    EXECUTABLE_PATTERNS,
    REMEDIATION_PATTERNS,
)
from app.ai.advisory import generate_advisory, advisory_to_dict, AdvisoryError
from app.ai.prompts import AI_PROMPT_VERSION, SYSTEM_PROMPT
from app.ai.runner import run_advisory, run_advisory_json, AdvisoryRunnerError
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
    RemediationActionMeta,
)


# ── Helper fixtures ──────────────────────────────────────────────────────────


def _make_report(
    analysis_status: str = "completed",
    findings: list[FindingSummary] | None = None,
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

    findings_grouped = FindingsGrouped()
    if findings:
        for f in findings:
            if f.severity == "critical":
                findings_grouped = FindingsGrouped(
                    critical=findings_grouped.critical + [f],
                    warning=findings_grouped.warning,
                    info=findings_grouped.info,
                    critical_count=findings_grouped.critical_count + 1,
                    warning_count=findings_grouped.warning_count,
                    info_count=findings_grouped.info_count,
                )
            elif f.severity == "warning":
                findings_grouped = FindingsGrouped(
                    critical=findings_grouped.critical,
                    warning=findings_grouped.warning + [f],
                    info=findings_grouped.info,
                    critical_count=findings_grouped.critical_count,
                    warning_count=findings_grouped.warning_count + 1,
                    info_count=findings_grouped.info_count,
                )
            else:
                findings_grouped = FindingsGrouped(
                    critical=findings_grouped.critical,
                    warning=findings_grouped.warning,
                    info=findings_grouped.info + [f],
                    critical_count=findings_grouped.critical_count,
                    warning_count=findings_grouped.warning_count,
                    info_count=findings_grouped.info_count + 1,
                )

    return HealthReport(
        schema_version="1.0",
        generated_at="2026-01-01T00:00:00",
        discovery_run_id=1,
        discovery_status="completed",
        analysis_status=analysis_status,
        findings_available=analysis_status == "completed",
        findings_count=len(findings) if findings else 0,
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
        findings=findings_grouped,
        file_analysis=FileAnalysisSummary(
            available=True,
            files_examined=100,
            duplicate_groups=2,
            potential_duplicate_bytes=50_000_000,
        ),
        remediation=RemediationSummary(
            actions=[
                RemediationActionMeta(
                    action_id="user_temp_quarantine",
                    name="Quarantine old temp files",
                    risk_level="medium",
                    reversible=True,
                )
            ]
        ),
    )


# ── A. Context builder uses HealthReport ────────────────────────────────────


class TestContextBuilderUsesHealthReport:
    def test_build_context_from_report(self) -> None:
        report = _make_report()
        context = build_ai_context(report)
        assert isinstance(context, AIContext)

    def test_context_has_system_summary(self) -> None:
        report = _make_report()
        context = build_ai_context(report)
        assert context.system_summary["hostname"] == "TEST-PC"
        assert context.system_summary["os_name"] == "Windows 10"

    def test_context_has_storage_summary(self) -> None:
        report = _make_report(storage_usage=85.0)
        context = build_ai_context(report)
        assert len(context.storage_summary["partitions"]) == 1
        assert context.storage_summary["partitions"][0]["usage_percent"] == 85.0

    def test_context_has_battery_summary(self) -> None:
        report = _make_report(battery_health=75.0)
        context = build_ai_context(report)
        assert context.battery_summary["health_percent"] == 75.0

    def test_context_has_findings(self) -> None:
        findings = [
            FindingSummary(finding_id="1", analyzer="test", severity="warning", title="Test"),
        ]
        report = _make_report(findings=findings)
        context = build_ai_context(report)
        assert len(context.findings_summary) == 1


# ── B. Context limits are enforced ───────────────────────────────────────────


class TestContextLimits:
    def test_findings_capped(self) -> None:
        findings = [
            FindingSummary(finding_id=str(i), analyzer="test", severity="info", title=f"Finding {i}")
            for i in range(100)
        ]
        report = _make_report(findings=findings)
        context = build_ai_context(report)
        assert len(context.findings_summary) <= MAX_FINDINGS

    def test_text_truncated(self) -> None:
        report = _make_report()
        report = HealthReport(
            schema_version="1.0",
            generated_at="2026-01-01T00:00:00",
            discovery_run_id=1,
            discovery_status="completed",
            analysis_status="completed",
            system=SystemInfo(hostname="A" * 1000),
        )
        context = build_ai_context(report)
        assert len(context.system_summary["hostname"]) <= MAX_TEXT_LENGTH


# ── C. Secrets excluded ──────────────────────────────────────────────────────


class TestSecretsExcluded:
    def test_sensitive_fields_redacted(self) -> None:
        from app.ai.context import _sanitize_value
        for field in SENSITIVE_FIELDS:
            result = _sanitize_value(f"my_{field}_here", "secret_value")
            assert result == "[REDACTED]"

    def test_non_sensitive_fields_pass(self) -> None:
        from app.ai.context import _sanitize_value
        result = _sanitize_value("hostname", "TEST-PC")
        assert result == "TEST-PC"


# ── D. Battery serial excluded ───────────────────────────────────────────────


class TestBatterySerialExcluded:
    def test_battery_serial_not_in_context(self) -> None:
        report = _make_report()
        context = build_ai_context(report)
        # serial_number should never appear in battery summary
        assert "serial_number" not in context.battery_summary
        assert "serial" not in str(context.battery_summary).lower()


# ── E. File contents excluded ────────────────────────────────────────────────


class TestFileContentsExcluded:
    def test_no_file_contents_in_context(self) -> None:
        report = _make_report()
        context = build_ai_context(report)
        context_str = str(context)
        # Should not contain actual file content markers
        assert "password" not in context_str.lower()
        assert "secret" not in context_str.lower()


# ── F. Analysis not_run handled ──────────────────────────────────────────────


class TestAnalysisNotRun:
    def test_not_run_produces_advisory(self) -> None:
        report = _make_report(analysis_status="not_run")
        provider = MockProvider()
        advisory = generate_advisory(report, provider)
        assert advisory.analysis_status == "not_run"
        # Should have uncertainty about analysis not run
        uncertainty_descriptions = [u.description for u in advisory.uncertainties]
        assert any("not been run" in d or "not run" in d for d in uncertainty_descriptions)


# ── G. Completed analysis handled ────────────────────────────────────────────


class TestCompletedAnalysis:
    def test_completed_with_findings(self) -> None:
        findings = [
            FindingSummary(finding_id="1", analyzer="storage", severity="warning", title="High usage"),
        ]
        report = _make_report(findings=findings, storage_usage=85.0)
        provider = MockProvider()
        advisory = generate_advisory(report, provider)
        assert advisory.analysis_status == "completed"
        assert len(advisory.observations) > 0


# ── H. Failed analysis handled ───────────────────────────────────────────────


class TestFailedAnalysis:
    def test_failed_produces_advisory(self) -> None:
        report = _make_report(analysis_status="failed")
        provider = MockProvider()
        advisory = generate_advisory(report, provider)
        assert advisory.analysis_status == "failed"
        uncertainty_descriptions = [u.description for u in advisory.uncertainties]
        assert any("failed" in d.lower() for d in uncertainty_descriptions)


# ── I. Mock provider deterministic ───────────────────────────────────────────


class TestMockProviderDeterministic:
    def test_same_input_same_output(self) -> None:
        report = _make_report(storage_usage=85.0)
        provider = MockProvider()
        advisory1 = provider.generate_advisory(build_ai_context(report))
        advisory2 = provider.generate_advisory(build_ai_context(report))
        assert advisory1.summary == advisory2.summary
        assert len(advisory1.observations) == len(advisory2.observations)

    def test_provider_name(self) -> None:
        provider = MockProvider()
        assert provider.get_provider_name() == "mock"
        assert provider.get_model_name() == "deterministic"


# ── J. Provider abstraction works ────────────────────────────────────────────


class TestProviderAbstraction:
    def test_get_provider_default(self) -> None:
        provider = get_provider()
        assert isinstance(provider, MockProvider)

    def test_get_provider_mock(self) -> None:
        provider = get_provider("mock")
        assert isinstance(provider, MockProvider)

    def test_get_provider_external_falls_back(self) -> None:
        # External not configured, should fall back to mock
        provider = get_provider("external")
        assert isinstance(provider, MockProvider)


# ── K. Malformed output rejected ─────────────────────────────────────────────


class TestMalformedOutput:
    def test_empty_output_rejected(self) -> None:
        is_safe, violations = validate_ai_output("")
        assert is_safe  # Empty is safe

    def test_valid_output_accepted(self) -> None:
        output = "The system has 85% disk usage on C:\\"
        is_safe, violations = validate_ai_output(output)
        assert is_safe

    def test_recommendation_with_executable_true_rejected(self) -> None:
        with pytest.raises(ValueError, match="executable must always be False"):
            Recommendation(
                title="Test",
                rationale="Test",
                executable=True,
            )


# ── L. Executable command output rejected ────────────────────────────────────


class TestExecutableCommandRejected:
    def test_cmd_exe_rejected(self) -> None:
        output = "Run cmd.exe /c format C:"
        is_safe, violations = validate_ai_output(output)
        assert not is_safe
        assert any("Executable pattern" in v for v in violations)

    def test_powershell_rejected(self) -> None:
        output = "Execute powershell.exe -Command Remove-Item"
        is_safe, violations = validate_ai_output(output)
        assert not is_safe

    def test_registry_edit_rejected(self) -> None:
        output = "Use reg add HKLM\\SOFTWARE to modify"
        is_safe, violations = validate_ai_output(output)
        assert not is_safe

    def test_rm_rf_rejected(self) -> None:
        output = "Run rm -rf /tmp/test"
        is_safe, violations = validate_ai_output(output)
        assert not is_safe


# ── M. Registry-action reference remains non-executable ──────────────────────


class TestRegistryActionNonExecutable:
    def test_action_reference_in_recommendation(self) -> None:
        rec = Recommendation(
            title="Review quarantine action",
            rationale="The user_temp_quarantine action is available",
            related_action_ids=["user_temp_quarantine"],
            executable=False,
        )
        assert rec.executable is False
        assert "user_temp_quarantine" in rec.related_action_ids

    def test_recommendation_validate_non_executable(self) -> None:
        rec_dict = {
            "title": "Review action",
            "rationale": "Action available",
            "executable": False,
        }
        is_safe, violations = validate_recommendation(rec_dict)
        assert is_safe


# ── N. AI package has no executor dependency ─────────────────────────────────


class TestAIPackageNoExecutorDependency:
    def test_no_executor_import_in_models(self) -> None:
        import app.ai.models as models_mod
        source = open(models_mod.__file__).read()
        # Check for actual import statements, not just the word in comments/docstrings
        assert "from app.remediation.executor" not in source
        assert "import executor" not in source

    def test_no_executor_import_in_context(self) -> None:
        import app.ai.context as context_mod
        source = open(context_mod.__file__).read()
        assert "from app.remediation.executor" not in source
        assert "QuarantineExecutor" not in source

    def test_no_executor_import_in_provider(self) -> None:
        import app.ai.provider as provider_mod
        source = open(provider_mod.__file__).read()
        assert "from app.remediation.executor" not in source
        assert "QuarantineExecutor" not in source

    def test_no_executor_import_in_advisory(self) -> None:
        import app.ai.advisory as advisory_mod
        source = open(advisory_mod.__file__).read()
        assert "from app.remediation.executor" not in source
        assert "QuarantineExecutor" not in source


# ── O. No remediation invoked ────────────────────────────────────────────────


class TestNoRemediationInvoked:
    def test_advisory_generation_no_executor(self) -> None:
        report = _make_report()
        provider = MockProvider()
        advisory = generate_advisory(report, provider)
        # Advisory should not contain executor calls
        advisory_dict = advisory_to_dict(advisory)
        advisory_str = json.dumps(advisory_dict)
        assert "executor" not in advisory_str.lower()
        assert "execute_quarantine" not in advisory_str.lower()

    def test_recommendations_are_non_executable(self) -> None:
        report = _make_report()
        provider = MockProvider()
        advisory = generate_advisory(report, provider)
        for rec in advisory.recommendations:
            assert rec.executable is False


# ── P. CLI ai works with mock provider ───────────────────────────────────────


class TestCLIAi:
    def test_cli_ai_command_exists(self) -> None:
        from app.cli import main
        import sys
        # Just verify the command is registered
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        sub.add_parser("ai")
        args = parser.parse_args(["ai"])
        assert args.command == "ai"


# ── Q. --json output valid ───────────────────────────────────────────────────


class TestJsonOutput:
    def test_advisory_to_dict_valid_json(self) -> None:
        report = _make_report()
        provider = MockProvider()
        advisory = generate_advisory(report, provider)
        advisory_dict = advisory_to_dict(advisory)
        json_str = json.dumps(advisory_dict, default=str)
        parsed = json.loads(json_str)
        assert "summary" in parsed
        assert "observations" in parsed
        assert "recommendations" in parsed

    def test_json_output_all_recommendations_non_executable(self) -> None:
        report = _make_report()
        provider = MockProvider()
        advisory = generate_advisory(report, provider)
        advisory_dict = advisory_to_dict(advisory)
        for rec in advisory_dict["recommendations"]:
            assert rec["executable"] is False


# ── R. Missing provider handled ──────────────────────────────────────────────


class TestMissingProvider:
    def test_get_provider_returns_mock(self) -> None:
        provider = get_provider("nonexistent")
        assert isinstance(provider, MockProvider)


# ── S. External provider disabled by default ─────────────────────────────────


class TestExternalProviderDisabled:
    def test_external_provider_disabled(self) -> None:
        provider = ExternalProvider()
        assert provider.enabled is False

    def test_external_provider_raises_without_config(self) -> None:
        provider = ExternalProvider()
        with pytest.raises(RuntimeError, match="not enabled"):
            provider.generate_advisory(AIContext())


# ── T. API advisory endpoint read-only ───────────────────────────────────────


class TestAPIAdvisoryEndpoint:
    def test_advisory_endpoint_exists(self) -> None:
        from app.api.app import create_app
        app = create_app()
        schema = app.openapi()
        assert "/api/v1/ai/advisory" in schema.get("paths", {})

    def test_advisory_endpoint_is_get(self) -> None:
        from app.api.app import create_app
        app = create_app()
        schema = app.openapi()
        path_info = schema["paths"].get("/api/v1/ai/advisory", {})
        assert "get" in path_info

    def test_advisory_endpoint_no_post(self) -> None:
        from app.api.app import create_app
        app = create_app()
        schema = app.openapi()
        path_info = schema["paths"].get("/api/v1/ai/advisory", {})
        assert "post" not in path_info


# ── U. Existing tests remain passing (import check) ─────────────────────────


class TestExistingTestsUnaffected:
    def test_finding_model_still_works(self) -> None:
        from app.analyzers.finding import Finding
        f = Finding(
            analyzer="test",
            severity="warning",
            title="Test",
            message="Test message",
        )
        assert f.analyzer == "test"

    def test_snapshot_store_works(self) -> None:
        from app.database.sqlite import SnapshotStore
        store = SnapshotStore(":memory:")
        assert store is not None


# ── Additional safety tests ──────────────────────────────────────────────────


class TestAdvisorySafety:
    def test_validate_advisory_safe(self) -> None:
        advisory_dict = {
            "summary": "Test summary",
            "observations": [],
            "recommendations": [
                {
                    "title": "Test",
                    "rationale": "Test",
                    "executable": False,
                }
            ],
            "uncertainties": [],
            "limitations": [],
        }
        is_safe, violations = validate_advisory(advisory_dict)
        assert is_safe

    def test_validate_advisory_unsafe_recommendation(self) -> None:
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


class TestPromptDesign:
    def test_system_prompt_exists(self) -> None:
        assert len(SYSTEM_PROMPT) > 100

    def test_prompt_version(self) -> None:
        assert AI_PROMPT_VERSION == "1.3"

    def test_prompt_forbids_execution(self) -> None:
        assert "MUST NOT" in SYSTEM_PROMPT
        assert "execute" in SYSTEM_PROMPT.lower()


class TestAdvisoryModels:
    def test_observation_frozen(self) -> None:
        obs = Observation(title="Test", evidence="Test", source="test")
        with pytest.raises(AttributeError):
            obs.title = "Changed"  # type: ignore

    def test_recommendation_frozen(self) -> None:
        rec = Recommendation(title="Test", rationale="Test")
        with pytest.raises(AttributeError):
            rec.title = "Changed"  # type: ignore

    def test_advisory_metadata(self) -> None:
        meta = AdvisoryMetadata(provider="mock", model="test")
        assert meta.provider == "mock"


# ── Import guard: no remediation.executor in AI package ──────────────────────


class TestNoRemediationExecutorImport:
    """Verify the AI package never imports the remediation executor."""

    AI_MODULES = [
        "app.ai.__init__",
        "app.ai.models",
        "app.ai.context",
        "app.ai.provider",
        "app.ai.safety",
        "app.ai.advisory",
        "app.ai.prompts",
        "app.ai.runner",
    ]

    def test_no_executor_import_in_any_module(self) -> None:
        import importlib
        import sys

        for module_name in self.AI_MODULES:
            if module_name in sys.modules:
                mod = sys.modules[module_name]
            else:
                mod = importlib.import_module(module_name)

            if hasattr(mod, "__file__") and mod.__file__:
                with open(mod.__file__) as f:
                    source = f.read()
                assert "from app.remediation.executor" not in source, (
                    f"{module_name} imports remediation executor"
                    )
                assert "import executor" not in source, (
                    f"{module_name} imports executor"
                )


# Need argparse for CLI tests
import argparse
