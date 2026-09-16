"""Scheduled-task analyzer -- documents limitations of current snapshot data."""

from __future__ import annotations

from typing import Any

from app.analyzers.finding import Finding


name = "scheduled_tasks"

_LIMITATION_MESSAGE = (
    "The current scheduled-task snapshot collects TaskName, TaskPath, State, "
    "Author, and Description. These fields alone do not contain enough reliable "
    "information to distinguish normal disabled tasks from anomalous conditions "
    "without a curated allowlist or baseline. No findings are produced for this "
    "category."
)


def analyze(snapshots: dict[str, Any]) -> list[Finding]:
    """Analyze scheduled-task snapshot for anomalous conditions.

    Limitation: the existing snapshot fields do not support reliable anomaly
    detection for scheduled tasks.  This analyzer returns no health findings.
    """
    # Intentionally returns no findings.  The limitation is documented here
    # and can be revisited when additional task data is collected.
    return []
