"""Orchestrates the safe v0.1 discovery run."""

from __future__ import annotations

from typing import Any

from app.collectors import battery, hardware, processes, services, software, startup, storage, tasks, windows
from app.collectors.result import CollectorResult
from app.database.sqlite import SnapshotStore

# Ordered mapping of category name -> collector function.
# Each function must accept no arguments and return a CollectorResult.
COLLECTORS: dict[str, Any] = {
    "hardware": hardware.collect_result,
    "storage": storage.collect_result,
    "windows_os": windows.collect_os,
    "windows_bios": windows.collect_bios,
    "windows_computer_system": windows.collect_computer_system,
    "software": software.collect_result,
    "startup": startup.collect_result,
    "services": services.collect_result,
    "scheduled_tasks": tasks.collect_result,
    "processes": processes.collect_result,
    "battery": battery.collect_result,
}


def _run_collector(category: str, collector_fn: Any) -> CollectorResult:
    """Run a single collector, catching any unexpected exceptions."""
    try:
        result = collector_fn()
        if not isinstance(result, CollectorResult):
            raise TypeError(
                f"{category} collector returned {type(result).__name__}, expected CollectorResult"
            )
        return result
    except Exception as exc:
        return CollectorResult(
            payload=None,
            status="failed",
            error_message=f"{type(exc).__name__}: {exc}",
        )


def run(store: SnapshotStore | None = None) -> tuple[dict[str, object], dict[str, object]]:
    """Execute a full discovery run.

    Returns:
        A tuple of (results, summary) where results maps category -> payload
        and summary is a machine-readable report of the run.
    """
    store = store or SnapshotStore()
    run_id = store.start_run()

    results: dict[str, object] = {}
    collector_statuses: dict[str, dict[str, object]] = {}
    overall_status = "completed"

    for category, collector_fn in COLLECTORS.items():
        cr = _run_collector(category, collector_fn)
        results[category] = cr.payload
        collector_statuses[category] = {
            "status": cr.status,
            "error_message": cr.error_message,
        }

        store.save(
            category,
            cr.payload,
            run_id=run_id,
            status=cr.status,
            error_message=cr.error_message,
        )

        if cr.status == "failed":
            overall_status = "completed_with_errors"

    store.complete_run(run_id, status=overall_status)

    statuses = [cs["status"] for cs in collector_statuses.values()]
    summary: dict[str, object] = {
        "run_id": run_id,
        "overall_status": overall_status,
        "collector_count": len(COLLECTORS),
        "successful_count": statuses.count("ok"),
        "empty_count": statuses.count("empty"),
        "not_supported_count": statuses.count("not_supported"),
        "failed_count": statuses.count("failed"),
        "collectors": collector_statuses,
    }

    return results, summary
