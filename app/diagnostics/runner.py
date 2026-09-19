"""Diagnostic runner that orchestrates all diagnostic modules.

A diagnostic run is distinct from discovery, analysis, and remediation.
It never aborts because one source is unavailable.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from app.diagnostics.analyzers import analyze_diagnostics
from app.diagnostics.devices import collect_devices
from app.diagnostics.disk import collect_disk_health
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticRun, DiagnosticStatus
from app.diagnostics.performance import collect_performance
from app.diagnostics.thermal import collect_thermal
from app.diagnostics.windows_health import collect_windows_health


def _run_one(
    name: str,
    collector_fn: Any,
) -> tuple[list[DiagnosticResult], str | None]:
    """Run a single diagnostic collector, isolating failures."""
    try:
        results = collector_fn()
        return results if isinstance(results, list) else [], None
    except Exception as exc:
        return [], f"{name}: {type(exc).__name__}: {exc}"


def run_diagnostics(
    discovery_run_id: int | None = None,
) -> DiagnosticRun:
    """Execute all diagnostic modules and return a complete DiagnosticRun.

    Each module is isolated — a failure in one does not prevent others from running.
    """
    all_results: list[DiagnosticResult] = []
    errors: list[dict[str, Any]] = []

    started_at = datetime.now(timezone.utc).isoformat()
    start_time = time.monotonic()

    collectors = [
        ("disk", DiagnosticCategory.DISK, collect_disk_health),
        ("thermal", DiagnosticCategory.THERMAL, collect_thermal),
        ("performance", DiagnosticCategory.PERFORMANCE, collect_performance),
        ("devices", DiagnosticCategory.DEVICES, collect_devices),
        ("windows", DiagnosticCategory.WINDOWS, collect_windows_health),
    ]

    for collector_name, _category, collector_fn in collectors:
        results, error = _run_one(collector_name, collector_fn)
        all_results.extend(results)
        if error:
            errors.append({
                "collector": collector_name,
                "error_type": "collector_failure",
                "error_message": error,
            })

    # Run diagnostic analyzers on collected results
    _findings = analyze_diagnostics(all_results)

    elapsed_ms = int((time.monotonic() - start_time) * 1000)
    completed_at = datetime.now(timezone.utc).isoformat()

    run = DiagnosticRun(
        discovery_run_id=discovery_run_id,
        started_at=started_at,
        completed_at=completed_at,
        status="completed" if not errors else "partial",
        results=all_results,
        errors=errors,
    )

    return run


def save_diagnostic_run(
    run: DiagnosticRun,
    store: Any = None,
) -> int | None:
    """Persist a diagnostic run to the database.

    Returns the run_id if saved, None if store is not available.
    """
    if store is None:
        return None

    try:
        return store.save_diagnostic_run(
            discovery_run_id=run.discovery_run_id,
            started_at=run.started_at,
            completed_at=run.completed_at,
            status=run.status,
            results=[{
                "diagnostic_id": r.diagnostic_id,
                "category": r.category.value,
                "status": r.status.value,
                "title": r.title,
                "summary": r.summary,
                "evidence": r.evidence,
                "source": r.source,
                "collected_at": r.collected_at,
                "limitations": r.limitations,
                "errors": r.errors,
            } for r in run.results],
            errors=run.errors,
        )
    except Exception:
        return None
