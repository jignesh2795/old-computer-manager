"""AI provider abstraction layer.

Providers are replaceable and never tied to one vendor.
No cloud provider is called automatically.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any

from app.ai.context import AIContext
from app.ai.models import AIAdvisory


class AIProvider(ABC):
    """Abstract base class for AI providers.

    Providers must:
    - Not execute remediation
    - Not modify the system
    - Not access secrets
    - Return structured advisory output
    """

    @abstractmethod
    def generate_advisory(self, context: AIContext) -> AIAdvisory:
        """Generate advisory from bounded context.

        Args:
            context: Bounded AIContext with sanitized information.

        Returns:
            Structured AIAdvisory with observations and recommendations.
        """
        ...

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the provider name."""
        ...

    @abstractmethod
    def get_model_name(self) -> str:
        """Return the model name."""
        ...


class MockProvider(AIProvider):
    """Deterministic mock provider for tests.

    Generates predictable structured advisories from supplied context.
    Does not consume API quotas or make network calls.
    """

    def generate_advisory(self, context: AIContext) -> AIAdvisory:
        """Generate deterministic advisory from context."""
        from datetime import datetime
        from app.ai.models import Observation, Recommendation, Uncertainty, Limitation, AdvisoryMetadata

        observations = []
        recommendations = []
        uncertainties = []
        limitations = []

        # Analyze storage
        for partition in context.storage_summary.get("partitions", []):
            usage = partition.get("usage_percent")
            device = partition.get("device", "unknown")
            if usage is not None:
                if usage >= 90:
                    observations.append(Observation(
                        title=f"High disk usage on {device}",
                        evidence=f"{device} is {usage:.1f}% full",
                        source="storage_analyzer",
                        severity="critical",
                        confidence="high",
                    ))
                    recommendations.append(Recommendation(
                        title=f"Review storage on {device}",
                        rationale=f"Evidence indicates {device} is at {usage:.1f}% capacity, which may affect system performance.",
                        risk_level="low",
                        requires_confirmation=False,
                        executable=False,
                    ))
                elif usage >= 80:
                    observations.append(Observation(
                        title=f"Elevated disk usage on {device}",
                        evidence=f"{device} is {usage:.1f}% full",
                        source="storage_analyzer",
                        severity="warning",
                        confidence="high",
                    ))

        # Analyze battery
        battery = context.battery_summary
        if battery.get("available"):
            health = battery.get("health_percent")
            if health is None:
                uncertainties.append(Uncertainty(
                    description="Battery health data unavailable",
                    impact="Cannot assess battery condition accurately",
                ))
            elif health < 60:
                observations.append(Observation(
                    title="Battery health is critical",
                    evidence=f"Battery health is {health:.1f}%",
                    source="battery_collector",
                    severity="critical",
                    confidence="high",
                ))

            if battery.get("baseline_status") == "non-baseline":
                limitations.append(Limitation(
                    description="Battery observation is non-baseline (hardware being replaced)",
                ))

        # Analyze findings
        findings = context.findings_summary
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        warning_count = sum(1 for f in findings if f.get("severity") == "warning")

        if critical_count > 0:
            observations.append(Observation(
                title=f"{critical_count} critical finding(s) detected",
                evidence=f"Analysis found {critical_count} critical issues",
                source="analyzer_runner",
                severity="critical",
                confidence="high",
            ))

        if warning_count > 0:
            observations.append(Observation(
                title=f"{warning_count} warning(s) detected",
                evidence=f"Analysis found {warning_count} warnings",
                source="analyzer_runner",
                severity="warning",
                confidence="high",
            ))

        # Check analysis status
        if context.analysis_status == "not_run":
            uncertainties.append(Uncertainty(
                description="Analysis has not been run",
                impact="Cannot provide findings-based recommendations",
            ))
        elif context.analysis_status == "failed":
            uncertainties.append(Uncertainty(
                description="Analysis failed to complete",
                impact="Partial or no findings available",
            ))

        # Check remediation metadata
        for action in context.remediation_metadata:
            action_id = action.get("action_id", "")
            if action_id:
                recommendations.append(Recommendation(
                    title=f"Action available: {action.get('name', action_id)}",
                    rationale=f"The {action_id} action is registered and available for manual execution.",
                    related_action_ids=[action_id],
                    risk_level=action.get("risk_level", "low"),
                    requires_confirmation=True,
                    executable=False,
                ))

        # Add general limitations
        limitations.append(Limitation(
            description="Advisory is based on point-in-time observations, not continuous monitoring",
        ))
        limitations.append(Limitation(
            description="File analysis may not cover all directories",
        ))

        # Build summary
        summary_parts = []
        if critical_count > 0:
            summary_parts.append(f"{critical_count} critical issue(s)")
        if warning_count > 0:
            summary_parts.append(f"{warning_count} warning(s)")
        if not summary_parts:
            summary_parts.append("No critical issues detected")

        summary = f"Advisory generated from context with {len(context.findings_summary)} finding(s). " + ", ".join(summary_parts) + "."

        return AIAdvisory(
            schema_version="1.0",
            generated_at=datetime.now().isoformat(),
            report_run_id=None,
            analysis_status=context.analysis_status,
            summary=summary,
            observations=observations[:MAX_OBSERVATIONS],
            recommendations=recommendations[:MAX_RECOMMENDATIONS],
            uncertainties=uncertainties,
            limitations=limitations,
            metadata=AdvisoryMetadata(
                provider="mock",
                model="deterministic",
                prompt_version="1.0",
                generated_at=datetime.now().isoformat(),
            ),
        )

    def get_provider_name(self) -> str:
        return "mock"

    def get_model_name(self) -> str:
        return "deterministic"


# Module-level constants for mock provider
MAX_OBSERVATIONS = 10
MAX_RECOMMENDATIONS = 5


class ExternalProvider(AIProvider):
    """External API provider (disabled by default).

    Requires explicit configuration via environment variables.
    Never called automatically.
    """

    def __init__(self) -> None:
        self._api_key = os.environ.get("AI_API_KEY", "")
        self._api_url = os.environ.get("AI_API_URL", "")
        self._enabled = bool(self._api_key and self._api_url)

    @property
    def enabled(self) -> bool:
        """Check if external provider is enabled."""
        return self._enabled

    def generate_advisory(self, context: AIContext) -> AIAdvisory:
        """Generate advisory using external API.

        Raises:
            RuntimeError: If provider is not enabled.
        """
        if not self._enabled:
            raise RuntimeError(
                "External AI provider is not enabled. "
                "Set AI_API_KEY and AI_API_URL environment variables."
            )
        # TODO: Implement actual external API call
        # This should use sanitized context only
        raise NotImplementedError("External provider not yet implemented")

    def get_provider_name(self) -> str:
        return "external"

    def get_model_name(self) -> str:
        return "unknown"


def get_provider(provider_name: str | None = None) -> AIProvider:
    """Get an AI provider by name.

    Args:
        provider_name: Name of the provider. If None, uses default (mock).

    Returns:
        AIProvider instance.
    """
    if provider_name == "external":
        provider = ExternalProvider()
        if provider.enabled:
            return provider
        # Fall back to mock if external not configured
        return MockProvider()
    # Default to mock provider
    return MockProvider()
