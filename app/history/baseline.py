"""Baseline comparison for historical metrics.

Implements baseline establishment and comparison with battery-specific rules.
"""

from __future__ import annotations

from app.history.models import MetricObservation, Baseline, BaselineStatus


# Thresholds for baseline comparison
# Battery health: degradation only reported if change exceeds this threshold
BATTERY_HEALTH_DEGRADATION_THRESHOLD: float = 5.0  # percentage points
# General metric: minimum change to report degradation/improvement
GENERAL_DEGRADATION_THRESHOLD: float = 2.0  # percentage points for %
GENERAL_COUNT_THRESHOLD: float = 0.10  # 10% relative for counts


def compute_baseline(
    observations: list[MetricObservation],
    current_value: float | None = None,
) -> Baseline:
    """Compute baseline for a metric from historical observations.

    The baseline is the first valid observation. Current value is the latest.

    Special rules:
    - Battery health: requires valid health_percent to establish baseline
    - Dead battery observations (0% health) are not used as baseline

    Args:
        observations: List of observations ordered by time (oldest first).
        current_value: Override for current value (e.g. from latest run).

    Returns:
        Baseline with status and comparison.
    """
    if not observations:
        return Baseline(
            metric_name="",
            baseline_status=BaselineStatus.UNAVAILABLE,
        )

    metric_name = observations[0].metric_name

    # Filter to valid observations
    valid = [o for o in observations if o.value is not None]

    if not valid:
        return Baseline(
            metric_name=metric_name,
            baseline_status=BaselineStatus.UNAVAILABLE,
        )

    # Battery health special rules
    if metric_name == "health_percent":
        return _battery_health_baseline(valid, current_value)

    # General baseline: first valid observation
    baseline_obs = valid[0]
    latest_obs = valid[-1]

    baseline_value = baseline_obs.value
    current = current_value if current_value is not None else latest_obs.value

    if baseline_value is None or current is None:
        return Baseline(
            metric_name=metric_name,
            baseline_status=BaselineStatus.INSUFFICIENT_DATA,
        )

    delta = current - baseline_value
    delta_percent = (delta / abs(baseline_value) * 100) if baseline_value != 0 else None

    status = _determine_baseline_status(
        delta, delta_percent, baseline_obs.unit
    )

    return Baseline(
        metric_name=metric_name,
        baseline_run_id=baseline_obs.discovery_run_id,
        baseline_timestamp=baseline_obs.timestamp,
        baseline_value=baseline_value,
        current_value=current,
        delta=delta,
        delta_percent=delta_percent,
        baseline_status=status,
    )


def _battery_health_baseline(
    valid_observations: list[MetricObservation],
    current_value: float | None,
) -> Baseline:
    """Compute baseline for battery health with special rules.

    Rules:
    - Baseline requires valid health_percent
    - Dead battery (0% or very low) is not used as baseline
    - Baseline established only when valid health data exists
    """
    metric_name = valid_observations[0].metric_name

    # Find first valid health observation (excluding dead battery)
    baseline_obs = None
    for obs in valid_observations:
        if obs.value is not None and obs.value > 0:
            baseline_obs = obs
            break

    if baseline_obs is None:
        return Baseline(
            metric_name=metric_name,
            baseline_status=BaselineStatus.UNAVAILABLE,
        )

    baseline_value = baseline_obs.value
    latest_obs = valid_observations[-1]
    current = current_value if current_value is not None else latest_obs.value

    if current is None:
        return Baseline(
            metric_name=metric_name,
            baseline_run_id=baseline_obs.discovery_run_id,
            baseline_timestamp=baseline_obs.timestamp,
            baseline_value=baseline_value,
            current_value=None,
            baseline_status=BaselineStatus.INSUFFICIENT_DATA,
        )

    delta = current - baseline_value
    delta_percent = (delta / abs(baseline_value) * 100) if baseline_value != 0 else None

    # Check if change exceeds degradation threshold
    if delta < -BATTERY_HEALTH_DEGRADATION_THRESHOLD:
        status = BaselineStatus.DEGRADED
    elif delta > BATTERY_HEALTH_DEGRADATION_THRESHOLD:
        status = BaselineStatus.IMPROVED
    else:
        status = BaselineStatus.UNCHANGED

    return Baseline(
        metric_name=metric_name,
        baseline_run_id=baseline_obs.discovery_run_id,
        baseline_timestamp=baseline_obs.timestamp,
        baseline_value=baseline_value,
        current_value=current,
        delta=delta,
        delta_percent=delta_percent,
        baseline_status=status,
    )


def _determine_baseline_status(
    delta: float,
    delta_percent: float | None,
    unit: str,
) -> BaselineStatus:
    """Determine baseline status from delta."""
    if unit == "%":
        if abs(delta) <= GENERAL_DEGRADATION_THRESHOLD:
            return BaselineStatus.UNCHANGED
    elif unit == "count":
        if delta_percent is not None and abs(delta_percent) <= GENERAL_COUNT_THRESHOLD * 100:
            return BaselineStatus.UNCHANGED
        if abs(delta) <= 1:
            return BaselineStatus.UNCHANGED
    elif unit == "bytes":
        if delta_percent is not None and abs(delta_percent) <= 10.0:
            return BaselineStatus.UNCHANGED
    else:
        if delta_percent is not None and abs(delta_percent) <= 5.0:
            return BaselineStatus.UNCHANGED

    if delta > 0:
        return BaselineStatus.IMPROVED
    elif delta < 0:
        return BaselineStatus.DEGRADED

    return BaselineStatus.UNCHANGED
