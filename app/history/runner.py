"""Historical analysis runner.

Orchestrates historical trend analysis, baseline comparison,
recurring findings, and anomaly detection.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from app.database.sqlite import SnapshotStore
from app.history.models import (
    HistoricalSummary,
    TrendResult,
    Baseline,
    HistoricalAnomaly,
    RecurringFinding,
    DataQuality,
    TrendDirection,
    BaselineStatus,
)
from app.history.repository import HistoryRepository
from app.history.trends import calculate_trend
from app.history.baseline import compute_baseline
from app.history.anomalies import detect_anomalies


# Maximum number of runs to consider for historical analysis
MAX_RUNS_DEFAULT: int = 50


def run_history(
    store: SnapshotStore,
    limit: int | None = None,
    metric: str | None = None,
) -> HistoricalSummary:
    """Run historical analysis on completed discovery runs.

    This is a read-only operation that analyzes existing data.

    Args:
        store: Database store.
        limit: Maximum number of runs to consider.
        metric: Optional filter to analyze only a specific metric.

    Returns:
        HistoricalSummary with trends, baselines, anomalies, and recurring findings.
    """
    repo = HistoryRepository(store)
    run_ids = repo.get_all_run_ids(limit=limit or MAX_RUNS_DEFAULT)

    if not run_ids:
        return HistoricalSummary(
            runs_considered=0,
            observations_available=0,
        )

    # Get all observations
    all_observations = repo.get_all_observations(run_ids)

    # Filter to specific metric if requested
    if metric:
        all_observations = {k: v for k, v in all_observations.items() if k == metric}

    # Calculate trends
    trends: list[TrendResult] = []
    baseline_results: list[Baseline] = []
    anomalies_list: list[HistoricalAnomaly] = []
    data_quality_list: list[DataQuality] = []

    for metric_name, observations in sorted(all_observations.items()):
        # Trend
        trend = calculate_trend(observations)
        trends.append(trend)

        # Baseline
        baseline = compute_baseline(observations)
        baseline_results.append(baseline)

        # Anomalies
        metric_anomalies = detect_anomalies(observations)
        anomalies_list.extend(metric_anomalies)

        # Data quality
        total = len(observations)
        valid = sum(1 for o in observations if o.value is not None)
        data_quality_list.append(
            DataQuality(
                metric_name=metric_name,
                total_observations=total,
                valid_observations=valid,
                missing_count=total - valid,
            )
        )

    # Recurring findings
    findings_history = repo.get_findings_history(run_ids)
    recurring = _find_recurring_findings(findings_history)

    return HistoricalSummary(
        runs_considered=len(run_ids),
        observations_available=sum(len(v) for v in all_observations.values()),
        trends=trends,
        baseline=baseline_results,
        recurring_findings=recurring,
        anomalies=anomalies_list,
        data_quality=data_quality_list,
        run_ids=tuple(run_ids),
    )


def _find_recurring_findings(
    findings: list[dict[str, Any]],
) -> list[RecurringFinding]:
    """Identify findings that appear across multiple runs."""
    # Group by (analyzer, title) - same finding across runs
    finding_groups: dict[tuple[str, str], dict[str, Any]] = {}

    for f in findings:
        key = (f["analyzer"], f["title"])
        if key not in finding_groups:
            finding_groups[key] = {
                "analyzer": f["analyzer"],
                "severity": f["severity"],
                "title": f["title"],
                "first_seen": f["created_at"],
                "last_seen": f["created_at"],
                "run_ids": set(),
            }
        group = finding_groups[key]
        group["run_ids"].add(f["run_id"])
        group["last_seen"] = f["created_at"]

    # Filter to findings that appear in more than one run
    recurring = []
    for key, group in sorted(finding_groups.items()):
        if len(group["run_ids"]) > 1:
            recurring.append(
                RecurringFinding(
                    analyzer=group["analyzer"],
                    severity=group["severity"],
                    title=group["title"],
                    first_seen=group["first_seen"],
                    last_seen=group["last_seen"],
                    occurrence_count=len(group["run_ids"]),
                    run_ids=tuple(sorted(group["run_ids"])),
                )
            )

    # Sort by occurrence count descending
    recurring.sort(key=lambda r: r.occurrence_count, reverse=True)

    return recurring


def run_history_json(
    store: SnapshotStore,
    limit: int | None = None,
    metric: str | None = None,
) -> str:
    """Run historical analysis and return JSON string.

    Args:
        store: Database store.
        limit: Maximum number of runs to consider.
        metric: Optional filter to analyze only a specific metric.

    Returns:
        JSON string of HistoricalSummary.
    """
    summary = run_history(store, limit=limit, metric=metric)
    return _summary_to_json(summary)


def _summary_to_json(summary: HistoricalSummary) -> str:
    """Convert HistoricalSummary to JSON string."""
    return json.dumps(
        {
            "runs_considered": summary.runs_considered,
            "observations_available": summary.observations_available,
            "run_ids": list(summary.run_ids),
            "trends": [
                {
                    "metric_name": t.metric_name,
                    "observations_count": t.observations_count,
                    "first_value": t.first_value,
                    "latest_value": t.latest_value,
                    "minimum": t.minimum,
                    "maximum": t.maximum,
                    "delta_absolute": t.delta_absolute,
                    "delta_percent": t.delta_percent,
                    "direction": t.direction.value,
                    "first_timestamp": t.first_timestamp,
                    "latest_timestamp": t.latest_timestamp,
                }
                for t in summary.trends
            ],
            "baseline": [
                {
                    "metric_name": b.metric_name,
                    "baseline_run_id": b.baseline_run_id,
                    "baseline_timestamp": b.baseline_timestamp,
                    "baseline_value": b.baseline_value,
                    "current_value": b.current_value,
                    "delta": b.delta,
                    "delta_percent": b.delta_percent,
                    "baseline_status": b.baseline_status.value,
                }
                for b in summary.baseline
            ],
            "recurring_findings": [
                {
                    "analyzer": r.analyzer,
                    "severity": r.severity,
                    "title": r.title,
                    "first_seen": r.first_seen,
                    "last_seen": r.last_seen,
                    "occurrence_count": r.occurrence_count,
                    "run_ids": list(r.run_ids),
                }
                for r in summary.recurring_findings
            ],
            "anomalies": [
                {
                    "metric_name": a.metric_name,
                    "severity": a.severity,
                    "title": a.title,
                    "message": a.message,
                    "evidence": a.evidence,
                    "first_detected": a.first_detected,
                    "last_detected": a.last_detected,
                    "occurrence_count": a.occurrence_count,
                }
                for a in summary.anomalies
            ],
            "data_quality": [
                {
                    "metric_name": d.metric_name,
                    "total_observations": d.total_observations,
                    "valid_observations": d.valid_observations,
                    "missing_count": d.missing_count,
                    "not_supported_count": d.not_supported_count,
                    "failed_count": d.failed_count,
                }
                for d in summary.data_quality
            ],
        },
        indent=2,
        default=str,
    )
