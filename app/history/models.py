"""Data models for historical analysis.

These models represent historical observations, trends, baselines, and anomalies.
They are frozen dataclasses for safety and consistency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TrendDirection(str, Enum):
    """Direction of a metric trend."""

    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    INSUFFICIENT_DATA = "insufficient_data"


class BaselineStatus(str, Enum):
    """Status of a metric baseline comparison."""

    UNAVAILABLE = "unavailable"
    ESTABLISHED = "established"
    IMPROVED = "improved"
    DEGRADED = "degraded"
    UNCHANGED = "unchanged"
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass(frozen=True)
class MetricObservation:
    """A single observation of a metric from a discovery run."""

    metric_name: str
    timestamp: str
    discovery_run_id: int
    value: float | None
    unit: str
    source: str  # category that produced this metric


@dataclass(frozen=True)
class TrendResult:
    """Result of trend analysis for a single metric."""

    metric_name: str
    observations_count: int
    first_value: float | None
    latest_value: float | None
    minimum: float | None
    maximum: float | None
    delta_absolute: float | None
    delta_percent: float | None
    direction: TrendDirection
    first_timestamp: str | None
    latest_timestamp: str | None


@dataclass(frozen=True)
class Baseline:
    """Baseline comparison result for a single metric."""

    metric_name: str
    baseline_run_id: int | None = None
    baseline_timestamp: str | None = None
    baseline_value: float | None = None
    current_value: float | None = None
    delta: float | None = None
    delta_percent: float | None = None
    baseline_status: BaselineStatus = BaselineStatus.UNAVAILABLE


@dataclass(frozen=True)
class HistoricalAnomaly:
    """A detected anomaly in historical data."""

    metric_name: str
    severity: str  # 'warning', 'critical', 'info'
    title: str
    message: str
    evidence: dict = field(default_factory=dict)
    first_detected: str | None = None
    last_detected: str | None = None
    occurrence_count: int = 0


@dataclass(frozen=True)
class RecurringFinding:
    """A finding that has appeared across multiple discovery runs."""

    analyzer: str
    severity: str
    title: str
    first_seen: str | None = None
    last_seen: str | None = None
    occurrence_count: int = 0
    run_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class DataQuality:
    """Data quality information for a metric."""

    metric_name: str
    total_observations: int
    valid_observations: int
    missing_count: int = 0
    not_supported_count: int = 0
    failed_count: int = 0


@dataclass(frozen=True)
class HistoricalSummary:
    """Complete historical analysis summary."""

    runs_considered: int = 0
    observations_available: int = 0
    trends: list[TrendResult] = field(default_factory=list)
    baseline: list[Baseline] = field(default_factory=list)
    recurring_findings: list[RecurringFinding] = field(default_factory=list)
    anomalies: list[HistoricalAnomaly] = field(default_factory=list)
    data_quality: list[DataQuality] = field(default_factory=list)
    run_ids: tuple[int, ...] = ()
