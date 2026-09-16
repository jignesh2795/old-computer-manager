"""Simple anomaly detection for historical metrics.

Implements only explainable, threshold-based anomalies.
No machine learning or speculative claims.
"""

from __future__ import annotations

from app.history.models import MetricObservation, HistoricalAnomaly


# Anomaly detection thresholds
# Sudden storage increase: more than 10 percentage points between consecutive runs
STORAGE_SUDDEN_INCREASE_THRESHOLD: float = 10.0
# Sudden battery health drop: more than 10 percentage points between consecutive runs
BATTERY_SUDDEN_DROP_THRESHOLD: float = 10.0
# Sudden startup count change: more than 50% relative change
STARTUP_SUDDEN_CHANGE_THRESHOLD: float = 0.50
# Sudden software count change: more than 20% relative change
SOFTWARE_SUDDEN_CHANGE_THRESHOLD: float = 0.20


def detect_anomalies(
    observations: list[MetricObservation],
) -> list[HistoricalAnomaly]:
    """Detect simple anomalies in a metric's observation history.

    Only detects obvious, explainable anomalies:
    - Sudden large changes between consecutive observations
    - Does not make speculative claims about causes

    Args:
        observations: List of observations ordered by time (oldest first).

    Returns:
        List of detected anomalies.
    """
    if len(observations) < 2:
        return []

    anomalies = []
    valid = [o for o in observations if o.value is not None]

    if len(valid) < 2:
        return []

    metric_name = valid[0].metric_name

    # Check for sudden changes between consecutive observations
    for i in range(1, len(valid)):
        prev = valid[i - 1]
        curr = valid[i]

        if prev.value == 0:
            continue

        delta = curr.value - prev.value
        delta_percent = abs(delta / abs(prev.value)) * 100

        anomaly = _check_sudden_change(
            metric_name, prev, curr, delta, delta_percent
        )
        if anomaly is not None:
            anomalies.append(anomaly)

    return anomalies


def _check_sudden_change(
    metric_name: str,
    prev: MetricObservation,
    curr: MetricObservation,
    delta: float,
    delta_percent: float,
) -> HistoricalAnomaly | None:
    """Check for sudden change anomaly based on metric type."""
    # Storage metrics
    if metric_name.startswith("storage_") and "percent_used" in metric_name:
        if delta > STORAGE_SUDDEN_INCREASE_THRESHOLD:
            return HistoricalAnomaly(
                metric_name=metric_name,
                severity="warning",
                title=f"Sudden storage increase: {metric_name}",
                message=(
                    f"Storage utilization increased by {delta:.1f} percentage points "
                    f"between runs {prev.discovery_run_id} and {curr.discovery_run_id}."
                ),
                evidence={
                    "previous_value": prev.value,
                    "current_value": curr.value,
                    "delta": delta,
                    "previous_run_id": prev.discovery_run_id,
                    "current_run_id": curr.discovery_run_id,
                },
                first_detected=prev.timestamp,
                last_detected=curr.timestamp,
                occurrence_count=1,
            )

    # Battery health
    if metric_name == "health_percent":
        if delta < -BATTERY_SUDDEN_DROP_THRESHOLD:
            return HistoricalAnomaly(
                metric_name=metric_name,
                severity="warning",
                title="Sudden battery health drop",
                message=(
                    f"Battery health dropped by {abs(delta):.1f} percentage points "
                    f"between runs {prev.discovery_run_id} and {curr.discovery_run_id}."
                ),
                evidence={
                    "previous_value": prev.value,
                    "current_value": curr.value,
                    "delta": delta,
                    "previous_run_id": prev.discovery_run_id,
                    "current_run_id": curr.discovery_run_id,
                },
                first_detected=prev.timestamp,
                last_detected=curr.timestamp,
                occurrence_count=1,
            )

    # Startup count
    if metric_name == "startup_count":
        if delta_percent > STARTUP_SUDDEN_CHANGE_THRESHOLD * 100:
            direction = "increased" if delta > 0 else "decreased"
            return HistoricalAnomaly(
                metric_name=metric_name,
                severity="info",
                title=f"Sudden startup count change",
                message=(
                    f"Startup count {direction} by {abs(delta):.0f} "
                    f"({delta_percent:.1f}%) between runs "
                    f"{prev.discovery_run_id} and {curr.discovery_run_id}."
                ),
                evidence={
                    "previous_value": prev.value,
                    "current_value": curr.value,
                    "delta": delta,
                    "delta_percent": delta_percent,
                    "previous_run_id": prev.discovery_run_id,
                    "current_run_id": curr.discovery_run_id,
                },
                first_detected=prev.timestamp,
                last_detected=curr.timestamp,
                occurrence_count=1,
            )

    # Software count
    if metric_name == "software_count":
        if delta_percent > SOFTWARE_SUDDEN_CHANGE_THRESHOLD * 100:
            direction = "increased" if delta > 0 else "decreased"
            return HistoricalAnomaly(
                metric_name=metric_name,
                severity="info",
                title=f"Sudden software count change",
                message=(
                    f"Software count {direction} by {abs(delta):.0f} "
                    f"({delta_percent:.1f}%) between runs "
                    f"{prev.discovery_run_id} and {curr.discovery_run_id}."
                ),
                evidence={
                    "previous_value": prev.value,
                    "current_value": curr.value,
                    "delta": delta,
                    "delta_percent": delta_percent,
                    "previous_run_id": prev.discovery_run_id,
                    "current_run_id": curr.discovery_run_id,
                },
                first_detected=prev.timestamp,
                last_detected=curr.timestamp,
                occurrence_count=1,
            )

    return None
