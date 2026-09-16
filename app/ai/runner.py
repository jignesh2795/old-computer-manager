"""AI advisory runner for CLI and API integration.

Runs the advisory generation pipeline:
1. Load latest completed report
2. Verify analysis state
3. Build bounded AI context
4. Call configured provider
5. Validate structured output
6. Return advisory
"""

from __future__ import annotations

import json
from typing import Any

from app.ai.advisory import generate_advisory, advisory_to_dict, AdvisoryError
from app.ai.models import AIAdvisory
from app.ai.provider import get_provider
from app.database.sqlite import SnapshotStore
from app.reporting.runner import generate_report
from app.reporting.models import HealthReport


class AdvisoryRunnerError(Exception):
    """Raised when advisory runner fails."""
    pass


def run_advisory(
    store: SnapshotStore | None = None,
    provider_name: str | None = None,
) -> AIAdvisory:
    """Run the advisory generation pipeline.

    This function:
    1. Loads the latest completed report
    2. Verifies analysis state
    3. Generates advisory using configured provider

    It does NOT:
    - Trigger discovery or analysis
    - Execute remediation
    - Modify the system

    Args:
        store: SnapshotStore to use. If None, creates default.
        provider_name: Name of provider to use. If None, uses default.

    Returns:
        Structured AIAdvisory.

    Raises:
        AdvisoryRunnerError: If advisory generation fails.
    """
    # Get or create store
    if store is None:
        store = SnapshotStore()

    # Generate report (read-only)
    try:
        report = generate_report(store)
    except Exception as e:
        raise AdvisoryRunnerError(f"Failed to generate report: {e}") from e

    # Check analysis status
    if report.analysis_status is None or report.analysis_status == "not_run":
        raise AdvisoryRunnerError(
            "Analysis has not been run. Run 'old-computer-manager analyze' first."
        )

    # Get provider
    provider = get_provider(provider_name)

    # Generate advisory
    try:
        advisory = generate_advisory(report, provider)
    except AdvisoryError as e:
        raise AdvisoryRunnerError(f"Advisory generation failed: {e}") from e

    # Set report run ID and include historical summary
    advisory = AIAdvisory(
        schema_version=advisory.schema_version,
        generated_at=advisory.generated_at,
        report_run_id=report.discovery_run_id,
        analysis_status=advisory.analysis_status,
        summary=advisory.summary,
        observations=advisory.observations,
        recommendations=advisory.recommendations,
        uncertainties=advisory.uncertainties,
        limitations=advisory.limitations,
        metadata=advisory.metadata,
        historical_summary=advisory.historical_summary,
    )

    return advisory


def run_advisory_json(
    store: SnapshotStore | None = None,
    provider_name: str | None = None,
) -> str:
    """Run advisory and return JSON string.

    Args:
        store: SnapshotStore to use. If None, creates default.
        provider_name: Name of provider to use. If None, uses default.

    Returns:
        JSON string of the advisory.
    """
    advisory = run_advisory(store, provider_name)
    advisory_dict = advisory_to_dict(advisory)
    return json.dumps(advisory_dict, indent=2, default=str)
