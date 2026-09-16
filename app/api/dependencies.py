"""Shared dependencies for API routes."""

from __future__ import annotations

from app.database.sqlite import SnapshotStore
from app.reporting.builder import build_health_report
from app.reporting.models import HealthReport

_store: SnapshotStore | None = None


def get_store() -> SnapshotStore:
    """Return the default SnapshotStore singleton."""
    global _store
    if _store is None:
        _store = SnapshotStore()
    return _store


def set_store(store: SnapshotStore) -> None:
    """Override the store (for testing)."""
    global _store
    _store = store


def reset_store() -> None:
    """Reset the store to default (for testing)."""
    global _store
    _store = None


def get_report() -> HealthReport:
    """Build and return the current health report.

    This reads existing database data and does not trigger
    any discovery, analysis, or filesystem operations.
    """
    store = get_store()
    return build_health_report(store)
