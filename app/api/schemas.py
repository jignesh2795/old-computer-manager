"""Pydantic models for API responses."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class SystemResponse(BaseModel):
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


class StoragePartitionResponse(BaseModel):
    device: str | None = None
    filesystem: str | None = None
    total_bytes: int | None = None
    used_bytes: int | None = None
    free_bytes: int | None = None
    usage_percent: float | None = None
    status: str | None = None


class StorageResponse(BaseModel):
    partitions: list[StoragePartitionResponse]
    count: int
    total_capacity_bytes: int | None = None
    total_free_bytes: int | None = None


class BatteryResponse(BaseModel):
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


class FindingResponse(BaseModel):
    finding_id: str | None = None
    analyzer: str
    severity: str
    title: str
    message: str
    evidence: Any = None
    recommendation: str | None = None
    created_at: str | None = None


class FindingsResponse(BaseModel):
    analysis_status: str | None = None
    findings_available: bool
    findings_count: int | None = None
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    findings: list[FindingResponse]


class FileAnalysisResponse(BaseModel):
    available: bool
    scan_root: str | None = None
    scan_timestamp: str | None = None
    files_examined: int = 0
    directories_examined: int = 0
    bytes_examined: int = 0
    files_skipped: int = 0
    symlinks_skipped: int = 0
    excluded_items: int = 0
    inaccessible_items: int = 0
    largest_files: list[dict[str, Any]]
    largest_directories: list[dict[str, Any]]
    file_type_summary: list[dict[str, Any]]
    duplicate_groups: int = 0
    potential_duplicate_bytes: int = 0


class RemediationActionResponse(BaseModel):
    action_id: str
    name: str
    risk_level: str
    reversible: bool
    requires_admin: bool
    preview_available: bool
    rollback_available: bool
    real_execution_exists: bool


class RemediationActionsResponse(BaseModel):
    actions: list[RemediationActionResponse]
    count: int


class ReportResponse(BaseModel):
    schema_version: str
    generated_at: str
    discovery_run_id: int | None = None
    discovery_status: str | None = None
    analysis_status: str | None = None
    findings_available: bool = False
    findings_count: int | None = None
    system: SystemResponse
    storage: StorageResponse
    battery: BatteryResponse
    findings: FindingsResponse
    software: dict[str, Any]
    startup: dict[str, Any]
    processes: dict[str, Any]
    services: dict[str, Any]
    scheduled_tasks: dict[str, Any]
    file_analysis: FileAnalysisResponse
    remediation: RemediationActionsResponse
    errors: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    detail: str


# AI Advisory schemas


class ObservationResponse(BaseModel):
    title: str
    evidence: str
    source: str
    severity: str = "info"
    confidence: str = "high"


class RecommendationResponse(BaseModel):
    title: str
    rationale: str
    related_finding_ids: list[str] = []
    related_action_ids: list[str] = []
    risk_level: str = "low"
    requires_confirmation: bool = True
    executable: bool = False  # MUST be False always


class UncertaintyResponse(BaseModel):
    description: str
    impact: str


class LimitationResponse(BaseModel):
    description: str


class AdvisoryMetadataResponse(BaseModel):
    provider: str = ""
    model: str = ""
    prompt_version: str = "1.0"
    generated_at: str = ""


class AdvisoryResponse(BaseModel):
    schema_version: str = "1.0"
    generated_at: str = ""
    report_run_id: int | None = None
    analysis_status: str | None = None
    summary: str = ""
    observations: list[ObservationResponse] = []
    recommendations: list[RecommendationResponse] = []
    uncertainties: list[UncertaintyResponse] = []
    limitations: list[LimitationResponse] = []
    metadata: AdvisoryMetadataResponse = AdvisoryMetadataResponse()
