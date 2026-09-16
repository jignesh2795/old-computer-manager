"""Local-first AI advisory layer for computer diagnostics.

This package provides read-only AI advisory capabilities.
The AI MUST NOT execute remediation, modify the system, or access secrets.
"""

from __future__ import annotations

from app.ai.models import (
    AIAdvisory,
    Observation,
    Recommendation,
    Uncertainty,
    Limitation,
    AdvisoryMetadata,
)
from app.ai.context import build_ai_context, AIContext
from app.ai.provider import AIProvider, get_provider
from app.ai.advisory import generate_advisory
from app.ai.runner import run_advisory

__all__ = [
    "AIAdvisory",
    "Observation",
    "Recommendation",
    "Uncertainty",
    "Limitation",
    "AdvisoryMetadata",
    "AIContext",
    "build_ai_context",
    "AIProvider",
    "get_provider",
    "generate_advisory",
    "run_advisory",
]
