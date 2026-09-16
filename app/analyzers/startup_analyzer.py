"""Startup analyzer -- detects unusually high startup entry counts."""

from __future__ import annotations

from typing import Any

from app.analyzers.constants import STARTUP_HIGH_COUNT
from app.analyzers.finding import Finding


name = "startup"


def analyze(snapshots: dict[str, Any]) -> list[Finding]:
    """Analyze startup snapshot for an unusually large number of entries.

    Threshold: more than STARTUP_HIGH_COUNT entries triggers a warning.
    """
    payload = snapshots.get("startup")
    if not payload or not isinstance(payload, list):
        return []

    count = len(payload)

    if count <= STARTUP_HIGH_COUNT:
        return []

    entries = [
        {"name": e.get("Name", ""), "command": e.get("Command", "")}
        for e in payload
    ]

    return [
        Finding(
            analyzer=name,
            severity="warning",
            title=f"Unusually high number of startup entries ({count})",
            message=(
                f"The system has {count} startup entries, which is above the "
                f"threshold of {STARTUP_HIGH_COUNT}. A high number of startup "
                f"entries can slow down boot time and increase resource usage."
            ),
            evidence={"count": count, "entries": entries},
            recommendation=(
                "Review the list of startup entries and consider disabling "
                "ones that are not regularly needed. This is informational "
                "only; no entries have been modified."
            ),
        )
    ]
