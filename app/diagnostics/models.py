"""Core models for diagnostic results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class DiagnosticStatus(str, Enum):
    """Status of a diagnostic observation.

    Do not confuse unavailable data with a hardware problem.
    """
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    UNAVAILABLE = "unavailable"
    NOT_SUPPORTED = "not_supported"
    FAILED = "failed"


class DiagnosticCategory(str, Enum):
    """Categories of diagnostics."""
    DISK = "disk"
    THERMAL = "thermal"
    PERFORMANCE = "performance"
    DEVICES = "devices"
    WINDOWS = "windows"
    EVENT_LOG = "event_log"
    RELIABILITY = "reliability"
    BOOT_TIMING = "boot_timing"
    NETWORK_HEALTH = "network_health"
    DRIVER_CONSISTENCY = "driver_consistency"


@dataclass(frozen=True)
class DiagnosticResult:
    """A single diagnostic observation.

    This is the core typed result for all diagnostic modules.
    It captures what was observed, not what should be done about it.
    collection_time_ms records how long collection took for regression detection.
    """
    diagnostic_id: str
    category: DiagnosticCategory
    status: DiagnosticStatus
    title: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    collection_time_ms: int = 0
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DiagnosticRun:
    """Result of a complete diagnostic run."""
    run_id: int | None = None
    discovery_run_id: int | None = None
    started_at: str = ""
    completed_at: str = ""
    status: str = "running"
    results: list[DiagnosticResult] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    total_time_ms: int = 0

    @property
    def disk_results(self) -> list[DiagnosticResult]:
        return [r for r in self.results if r.category == DiagnosticCategory.DISK]

    @property
    def thermal_results(self) -> list[DiagnosticResult]:
        return [r for r in self.results if r.category == DiagnosticCategory.THERMAL]

    @property
    def performance_results(self) -> list[DiagnosticResult]:
        return [r for r in self.results if r.category == DiagnosticCategory.PERFORMANCE]

    @property
    def device_results(self) -> list[DiagnosticResult]:
        return [r for r in self.results if r.category == DiagnosticCategory.DEVICES]

    @property
    def windows_results(self) -> list[DiagnosticResult]:
        return [r for r in self.results if r.category == DiagnosticCategory.WINDOWS]

    @property
    def event_log_results(self) -> list[DiagnosticResult]:
        return [r for r in self.results if r.category == DiagnosticCategory.EVENT_LOG]

    @property
    def reliability_results(self) -> list[DiagnosticResult]:
        return [r for r in self.results if r.category == DiagnosticCategory.RELIABILITY]

    @property
    def boot_timing_results(self) -> list[DiagnosticResult]:
        return [r for r in self.results if r.category == DiagnosticCategory.BOOT_TIMING]

    @property
    def network_health_results(self) -> list[DiagnosticResult]:
        return [r for r in self.results if r.category == DiagnosticCategory.NETWORK_HEALTH]

    @property
    def driver_consistency_results(self) -> list[DiagnosticResult]:
        return [r for r in self.results if r.category == DiagnosticCategory.DRIVER_CONSISTENCY]

    @property
    def summary_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            key = result.status.value
            counts[key] = counts.get(key, 0) + 1
        return counts
