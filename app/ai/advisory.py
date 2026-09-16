"""AI advisory generation.

Generates advisory based on current findings.
The AI must NOT execute remediation or modify the system.
"""

from __future__ import annotations

from typing import Any

from app.ai.context import AIContext, build_ai_context
from app.ai.models import AIAdvisory
from app.ai.provider import AIProvider, get_provider
from app.ai.safety import validate_advisory
from app.reporting.models import HealthReport


class AdvisoryError(Exception):
    """Raised when advisory generation fails."""
    pass


def generate_advisory(
    report: HealthReport,
    provider: AIProvider | None = None,
) -> AIAdvisory:
    """Generate AI advisory from HealthReport.

    This function:
    1. Builds bounded context from HealthReport
    2. Calls the configured provider
    3. Validates the output for safety
    4. Returns structured advisory

    It does NOT:
    - Execute remediation
    - Modify the system
    - Access secrets
    - Make network calls (unless external provider is explicitly configured)

    Args:
        report: HealthReport to generate advisory from.
        provider: AIProvider to use. If None, uses default (mock).

    Returns:
        Structured AIAdvisory.

    Raises:
        AdvisoryError: If advisory generation fails.
    """
    # Build bounded context
    context = build_ai_context(report)

    # Get provider
    if provider is None:
        provider = get_provider()

    # Generate advisory
    try:
        advisory = provider.generate_advisory(context)
    except Exception as e:
        raise AdvisoryError(f"Failed to generate advisory: {e}") from e

    # Validate advisory safety
    advisory_dict = {
        "summary": advisory.summary,
        "observations": [
            {
                "title": obs.title,
                "evidence": obs.evidence,
                "source": obs.source,
                "severity": obs.severity,
                "confidence": obs.confidence,
            }
            for obs in advisory.observations
        ],
        "recommendations": [
            {
                "title": rec.title,
                "rationale": rec.rationale,
                "related_finding_ids": rec.related_finding_ids,
                "related_action_ids": rec.related_action_ids,
                "risk_level": rec.risk_level,
                "requires_confirmation": rec.requires_confirmation,
                "executable": rec.executable,
            }
            for rec in advisory.recommendations
        ],
        "uncertainties": [
            {
                "description": unc.description,
                "impact": unc.impact,
            }
            for unc in advisory.uncertainties
        ],
        "limitations": [
            {"description": lim.description}
            for lim in advisory.limitations
        ],
    }

    is_safe, violations = validate_advisory(advisory_dict)
    if not is_safe:
        raise AdvisoryError(
            f"Advisory failed safety validation: {'; '.join(violations)}"
        )

    # Ensure recommendations are never executable
    for rec in advisory.recommendations:
        if rec.executable:
            raise AdvisoryError("Recommendation has executable=True (must be False)")

    return advisory


def advisory_to_dict(advisory: AIAdvisory) -> dict[str, Any]:
    """Convert AIAdvisory to dictionary for JSON serialization.

    Args:
        advisory: AIAdvisory to convert.

    Returns:
        Dictionary representation.
    """
    result: dict[str, Any] = {
        "schema_version": advisory.schema_version,
        "generated_at": advisory.generated_at,
        "report_run_id": advisory.report_run_id,
        "analysis_status": advisory.analysis_status,
        "summary": advisory.summary,
        "observations": [
            {
                "title": obs.title,
                "evidence": obs.evidence,
                "source": obs.source,
                "severity": obs.severity,
                "confidence": obs.confidence,
            }
            for obs in advisory.observations
        ],
        "recommendations": [
            {
                "title": rec.title,
                "rationale": rec.rationale,
                "related_finding_ids": rec.related_finding_ids,
                "related_action_ids": rec.related_action_ids,
                "risk_level": rec.risk_level,
                "requires_confirmation": rec.requires_confirmation,
                "executable": rec.executable,
            }
            for rec in advisory.recommendations
        ],
        "uncertainties": [
            {
                "description": unc.description,
                "impact": unc.impact,
            }
            for unc in advisory.uncertainties
        ],
        "limitations": [
            {"description": lim.description}
            for lim in advisory.limitations
        ],
        "metadata": {
            "provider": advisory.metadata.provider,
            "model": advisory.metadata.model,
            "prompt_version": advisory.metadata.prompt_version,
            "generated_at": advisory.metadata.generated_at,
        },
    }

    # Include historical summary if present
    if advisory.historical_summary is not None:
        result["historical_summary"] = {
            "runs_considered": advisory.historical_summary.runs_considered,
            "observations_used": advisory.historical_summary.observations_used,
            "trends_count": advisory.historical_summary.trends_count,
            "baselines_established": advisory.historical_summary.baselines_established,
            "recurring_findings_count": advisory.historical_summary.recurring_findings_count,
            "anomalies_count": advisory.historical_summary.anomalies_count,
            "data_quality_issues": advisory.historical_summary.data_quality_issues,
            "limited_by": advisory.historical_summary.limited_by,
        }

    return result
