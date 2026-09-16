"""Historical analysis package for tracking system changes over time.

This package provides read-only historical analysis of discovery runs.
It does not execute remediation, modify the system, or perform monitoring.
"""

from app.history.models import (
    MetricObservation,
    TrendResult,
    Baseline,
    HistoricalAnomaly,
    TrendDirection,
    BaselineStatus,
    HistoricalSummary,
)
from app.history.repository import HistoryRepository
from app.history.runner import run_history, run_history_json


__all__ = [
    "MetricObservation",
    "TrendResult",
    "Baseline",
    "HistoricalAnomaly",
    "TrendDirection",
    "BaselineStatus",
    "HistoricalSummary",
    "HistoryRepository",
    "run_history",
    "run_history_json",
]
