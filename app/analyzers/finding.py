"""Common finding model for analyzer results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Finding:
    """A single health finding produced by an analyzer.

    Attributes:
        analyzer: Name of the analyzer that produced this finding.
        severity: One of 'info', 'warning', 'critical'.
        title: Short human-readable title.
        message: Detailed explanation of the finding.
        evidence: Structured data supporting the finding (dict, list, or scalar).
        recommendation: Informational suggestion (not an automatic action).
        metadata: Optional extra key-value pairs for later consumption.
    """

    analyzer: str
    severity: str
    title: str
    message: str
    evidence: Any = None
    recommendation: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
