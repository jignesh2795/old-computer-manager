"""Trend calculation for historical metrics.

Implements conservative trend detection with configurable thresholds.
"""

from __future__ import annotations

from app.history.models import MetricObservation, TrendResult, TrendDirection


# Trend thresholds
# Minimum number of observations to establish a trend
MIN_OBSERVATIONS_FOR_TREND = 2
# Minimum absolute change to report as increasing/decreasing
# For percentage metrics: 2.0 percentage points
# For count metrics: 5% relative change
# For bytes metrics: 10% relative change
STABLE_THRESHOLD_PERCENT: float = 2.0  # percentage points for %
STABLE_THRESHOLD_COUNT_RELATIVE: float = 0.05  # 5% for counts
STABLE_THRESHOLD_BYTES_RELATIVE: float = 0.10  # 10% for bytes


def calculate_trend(
    observations: list[MetricObservation],
    unit: str | None = None,
) -> TrendResult:
    """Calculate trend from a list of observations.

    Args:
        observations: List of observations, ordered by time (oldest first).
        unit: Override unit for threshold selection.

    Returns:
        TrendResult with direction, deltas, and statistics.
    """
    if not observations:
        return TrendResult(
            metric_name="",
            observations_count=0,
            first_value=None,
            latest_value=None,
            minimum=None,
            maximum=None,
            delta_absolute=None,
            delta_percent=None,
            direction=TrendDirection.INSUFFICIENT_DATA,
            first_timestamp=None,
            latest_timestamp=None,
        )

    # Filter to valid observations only
    valid = [o for o in observations if o.value is not None]

    if not valid:
        return TrendResult(
            metric_name=observations[0].metric_name if observations else "",
            observations_count=0,
            first_value=None,
            latest_value=None,
            minimum=None,
            maximum=None,
            delta_absolute=None,
            delta_percent=None,
            direction=TrendDirection.INSUFFICIENT_DATA,
            first_timestamp=None,
            latest_timestamp=None,
        )

    metric_name = valid[0].metric_name
    first = valid[0]
    latest = valid[-1]
    values = [o.value for o in valid]

    first_value = first.value
    latest_value = latest.value
    minimum = min(values)
    maximum = max(values)

    # Calculate deltas
    delta_absolute = latest_value - first_value if first_value is not None and latest_value is not None else None
    delta_percent = None
    if first_value is not None and latest_value is not None and first_value != 0:
        delta_percent = ((latest_value - first_value) / abs(first_value)) * 100

    # Determine direction
    direction = _determine_direction(
        valid, unit or (observations[0].unit if observations else ""),
        delta_absolute, delta_percent,
    )

    return TrendResult(
        metric_name=metric_name,
        observations_count=len(valid),
        first_value=first_value,
        latest_value=latest_value,
        minimum=minimum,
        maximum=maximum,
        delta_absolute=delta_absolute,
        delta_percent=delta_percent,
        direction=direction,
        first_timestamp=first.timestamp,
        latest_timestamp=latest.timestamp,
    )


def _determine_direction(
    observations: list[MetricObservation],
    unit: str,
    delta_absolute: float | None,
    delta_percent: float | None,
) -> TrendDirection:
    """Determine the trend direction from observations and deltas."""
    if len(observations) < MIN_OBSERVATIONS_FOR_TREND:
        return TrendDirection.INSUFFICIENT_DATA

    if delta_absolute is None:
        return TrendDirection.INSUFFICIENT_DATA

    # Select threshold based on unit
    if unit == "%":
        threshold = STABLE_THRESHOLD_PERCENT
        if abs(delta_absolute) <= threshold:
            return TrendDirection.STABLE
    elif unit == "count":
        threshold = STABLE_THRESHOLD_COUNT_RELATIVE
        if delta_percent is not None and abs(delta_percent) <= threshold * 100:
            return TrendDirection.STABLE
        # For very small counts, use absolute threshold
        if abs(delta_absolute) <= 1:
            return TrendDirection.STABLE
    elif unit == "bytes":
        threshold = STABLE_THRESHOLD_BYTES_RELATIVE
        if delta_percent is not None and abs(delta_percent) <= threshold * 100:
            return TrendDirection.STABLE
    else:
        # Default: use 5% relative threshold
        if delta_percent is not None and abs(delta_percent) <= 5.0:
            return TrendDirection.STABLE

    if delta_absolute > 0:
        return TrendDirection.INCREASING
    elif delta_absolute < 0:
        return TrendDirection.DECREASING

    return TrendDirection.STABLE
