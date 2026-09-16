"""Service analyzer -- documents limitations of current snapshot data."""

from __future__ import annotations

from typing import Any

from app.analyzers.finding import Finding


name = "services"

_LIMITATION_MESSAGE = (
    "The current service snapshot collects Name, DisplayName, State, StartMode, "
    "StartName, and PathName. These fields alone do not contain enough reliable "
    "information to distinguish normal stopped/disabled services from anomalous "
    "conditions without a curated allowlist or baseline. No findings are produced "
    "for this category."
)


def analyze(snapshots: dict[str, Any]) -> list[Finding]:
    """Analyze service snapshot for anomalous conditions.

    Limitation: the existing snapshot fields do not support reliable anomaly
    detection for services.  This analyzer returns no health findings.
    """
    # Intentionally returns no findings.  The limitation is documented here
    # and can be revisited when additional service data is collected.
    return []
