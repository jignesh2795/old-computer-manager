"""Data models for the unified health report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class SystemInfo:
    hostname: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    architecture: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    bios_vendor: str | None = None
    bios_version: str | None = None
    cpu_name: str | None = None
    cpu_cores_physical: int | None = None
    cpu_cores_logical: int | None = None
    ram_total_bytes: int | None = None


@dataclass(frozen=True)
class StoragePartitionSummary:
    device: str | None = None
    filesystem: str | None = None
    total_bytes: int | None = None
    used_bytes: int | None = None
    free_bytes: int | None = None
    usage_percent: float | None = None
    status: str | None = None  # normal, warning, critical, unknown


@dataclass(frozen=True)
class StorageSummary:
    partitions: list[StoragePartitionSummary] = field(default_factory=list)
    count: int = 0
    total_capacity_bytes: int | None = None
    total_free_bytes: int | None = None


@dataclass(frozen=True)
class BatterySummary:
    available: bool | None = None
    status: str | None = None
    charge_percent: float | None = None
    plugged_in: bool | None = None
    design_capacity_mwh: int | None = None
    full_charge_capacity_mwh: int | None = None
    remaining_capacity_mwh: int | None = None
    health_percent: float | None = None
    wear_percent: float | None = None
    health_status: str | None = None
    cycle_count: int | None = None
    manufacturer: str | None = None
    battery_name: str | None = None
    baseline_status: str = "non-baseline"


@dataclass(frozen=True)
class FindingSummary:
    finding_id: str | None = None
    analyzer: str = ""
    severity: str = ""
    title: str = ""
    message: str = ""
    evidence: Any = None
    recommendation: str | None = None
    created_at: str | None = None


@dataclass(frozen=True)
class FindingsGrouped:
    critical: list[FindingSummary] = field(default_factory=list)
    warning: list[FindingSummary] = field(default_factory=list)
    info: list[FindingSummary] = field(default_factory=list)
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0


@dataclass(frozen=True)
class InstalledSoftwareSummary:
    count: int = 0


@dataclass(frozen=True)
class StartupSummary:
    count: int = 0


@dataclass(frozen=True)
class ProcessSummary:
    count: int = 0


@dataclass(frozen=True)
class ServiceSummary:
    count: int = 0


@dataclass(frozen=True)
class ScheduledTaskSummary:
    count: int = 0


@dataclass(frozen=True)
class FileAnalysisSummary:
    available: bool = False
    scan_root: str | None = None
    scan_timestamp: str | None = None
    files_examined: int = 0
    directories_examined: int = 0
    bytes_examined: int = 0
    files_skipped: int = 0
    symlinks_skipped: int = 0
    excluded_items: int = 0
    inaccessible_items: int = 0
    largest_files: list[dict[str, Any]] = field(default_factory=list)
    largest_directories: list[dict[str, Any]] = field(default_factory=list)
    file_type_summary: list[dict[str, Any]] = field(default_factory=list)
    duplicate_groups: int = 0
    potential_duplicate_bytes: int = 0


@dataclass(frozen=True)
class RemediationActionMeta:
    action_id: str = ""
    name: str = ""
    risk_level: str = ""
    reversible: bool = False
    requires_admin: bool = False
    preview_available: bool = False
    rollback_available: bool = False
    real_execution_exists: bool = False
    implementation_status: str = "not_implemented"
    blast_radius: str = "single_file"
    rollback_category: str = "not_applicable"
    eligibility: str = "requires_design_review"
    category: str = "general"
    action_version: str = "1"


@dataclass(frozen=True)
class RemediationSummary:
    actions: list[RemediationActionMeta] = field(default_factory=list)


@dataclass(frozen=True)
class ActionCandidateSummary:
    """Bounded summary of action candidates for the health report."""
    available_count: int = 0
    proposed_count: int = 0
    blocked_count: int = 0
    insufficient_evidence_count: int = 0
    stale_count: int = 0
    total_count: int = 0
    candidates: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class DiagnosticsSummary:
    available: bool = False
    run_id: int | None = None
    status: str | None = None
    result_count: int = 0
    categories: list[str] = field(default_factory=list)
    status_counts: dict[str, int] = field(default_factory=dict)
    results: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ReportError:
    component: str = ""
    stage: str = ""
    message: str = ""
    severity: str = "warning"


@dataclass(frozen=True)
class HealthReport:
    schema_version: str = "1.0"
    generated_at: str = ""
    discovery_run_id: int | None = None
    discovery_status: str | None = None
    analysis_status: str | None = None  # not_run, completed, failed, partial
    findings_available: bool = False
    findings_count: int | None = None
    system: SystemInfo = field(default_factory=SystemInfo)
    storage: StorageSummary = field(default_factory=StorageSummary)
    battery: BatterySummary = field(default_factory=BatterySummary)
    findings: FindingsGrouped = field(default_factory=FindingsGrouped)
    software: InstalledSoftwareSummary = field(default_factory=InstalledSoftwareSummary)
    startup: StartupSummary = field(default_factory=StartupSummary)
    processes: ProcessSummary = field(default_factory=ProcessSummary)
    services: ServiceSummary = field(default_factory=ServiceSummary)
    scheduled_tasks: ScheduledTaskSummary = field(default_factory=ScheduledTaskSummary)
    file_analysis: FileAnalysisSummary = field(default_factory=FileAnalysisSummary)
    remediation: RemediationSummary = field(default_factory=RemediationSummary)
    action_candidates: ActionCandidateSummary = field(default_factory=ActionCandidateSummary)
    diagnostics: DiagnosticsSummary = field(default_factory=DiagnosticsSummary)
    errors: list[ReportError] = field(default_factory=list)
