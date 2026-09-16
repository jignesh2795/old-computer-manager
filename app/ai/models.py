"""AI advisory data models.

All models are frozen dataclasses for immutability.
Recommendations must NEVER contain executable commands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Observation:
    """A factual observation derived from evidence.

    Observations must be grounded in supplied data.
    The AI must distinguish measured facts from inference.
    """

    title: str
    evidence: str
    source: str  # e.g., "storage_analyzer", "battery_collector"
    severity: str = "info"  # info, warning, critical
    confidence: str = "high"  # high, medium, low


@dataclass(frozen=True)
class Recommendation:
    """A safe next-step recommendation.

    Recommendations must NEVER contain executable commands.
    They reference actions but never invoke them.
    """

    title: str
    rationale: str
    related_finding_ids: list[str] = field(default_factory=list)
    related_action_ids: list[str] = field(default_factory=list)
    risk_level: str = "low"  # low, medium, high
    requires_confirmation: bool = True
    executable: bool = False  # MUST be False always

    def __post_init__(self) -> None:
        if self.executable:
            raise ValueError(
                "Recommendation.executable must always be False. "
                "The AI layer must not produce executable commands."
            )


@dataclass(frozen=True)
class Uncertainty:
    """Explicitly listed missing or uncertain information.

    This is essential for preventing hallucinations.
    """

    description: str
    impact: str  # How this limits the advisory


@dataclass(frozen=True)
class Limitation:
    """Known limitations of the current advisory."""

    description: str


@dataclass(frozen=True)
class AdvisoryMetadata:
    """Metadata about the advisory generation."""

    provider: str = ""
    model: str = ""
    prompt_version: str = "1.0"
    generated_at: str = ""
    context_tokens_estimate: int = 0
    usage: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AIAdvisory:
    """Complete AI advisory output.

    The advisory provides understand -> explain -> prioritize -> suggest.
    It does NOT execute, modify, or mutate anything.
    """

    schema_version: str = "1.0"
    generated_at: str = ""
    report_run_id: int | None = None
    analysis_status: str | None = None
    summary: str = ""
    observations: list[Observation] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
    uncertainties: list[Uncertainty] = field(default_factory=list)
    limitations: list[Limitation] = field(default_factory=list)
    metadata: AdvisoryMetadata = field(default_factory=AdvisoryMetadata)
