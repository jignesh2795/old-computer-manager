"""Build a unified HealthReport from existing database data."""

from __future__ import annotations

import json
from typing import Any

from app.analyzers.constants import STORAGE_CRITICAL_THRESHOLD, STORAGE_WARNING_THRESHOLD
from app.database.sqlite import SnapshotStore
from app.reporting.models import (
    BatterySummary,
    FindingSummary,
    FindingsGrouped,
    FileAnalysisSummary,
    HealthReport,
    InstalledSoftwareSummary,
    ProcessSummary,
    RemediationActionMeta,
    RemediationSummary,
    ReportError,
    ScheduledTaskSummary,
    ServiceSummary,
    StartupSummary,
    StoragePartitionSummary,
    StorageSummary,
    SystemInfo,
)

SCHEMA_VERSION = "1.0"


def _build_system_info(snapshots: dict[str, Any]) -> SystemInfo:
    hw = snapshots.get("hardware", {})
    os_info = snapshots.get("windows_os", {})
    cs = snapshots.get("windows_computer_system", {})
    bios = snapshots.get("windows_bios", {})

    # Handle both flat hardware format (real) and nested format (test mocks)
    hostname = hw.get("hostname") or cs.get("Name")
    os_name = os_info.get("Caption")
    os_version = os_info.get("Version")
    arch = os_info.get("OSArchitecture")
    manufacturer = cs.get("Manufacturer") or hw.get("manufacturer")
    model = cs.get("Model") or hw.get("model")
    cpu_name = hw.get("processor") or hw.get("cpu_name")
    cpu_phys = hw.get("cpu_physical_cores") or hw.get("cores_physical")
    cpu_log = hw.get("cpu_logical_cores") or hw.get("cores_logical")
    ram = hw.get("memory_total_bytes") or hw.get("total_physical_memory") or cs.get("TotalPhysicalMemory")
    bios_vendor = bios.get("Manufacturer") or hw.get("bios_vendor")
    bios_version = bios.get("SMBIOSBIOSVersion") or hw.get("bios_version")

    return SystemInfo(
        hostname=hostname,
        os_name=os_name,
        os_version=os_version,
        architecture=arch,
        manufacturer=manufacturer,
        model=model,
        bios_vendor=bios_vendor,
        bios_version=bios_version,
        cpu_name=cpu_name,
        cpu_cores_physical=cpu_phys,
        cpu_cores_logical=cpu_log,
        ram_total_bytes=ram,
    )


def _storage_status(usage: float) -> str:
    if usage >= STORAGE_CRITICAL_THRESHOLD:
        return "critical"
    if usage >= STORAGE_WARNING_THRESHOLD:
        return "warning"
    return "normal"


def _build_storage_summary(snapshots: dict[str, Any]) -> StorageSummary:
    storage = snapshots.get("storage", [])
    # Handle both list format (real) and dict-with-partitions key (test mocks)
    if isinstance(storage, dict):
        partitions_data = storage.get("partitions", [])
    else:
        partitions_data = storage
    partitions = []
    total_capacity = 0
    total_free = 0
    for p in partitions_data:
        usage = p.get("percent_used") or p.get("usage_percent") or 0.0
        total = p.get("total_bytes") or 0
        free = p.get("free_bytes") or 0
        partitions.append(
            StoragePartitionSummary(
                device=p.get("device") or p.get("mountpoint"),
                filesystem=p.get("filesystem") or p.get("fstype"),
                total_bytes=total or None,
                used_bytes=p.get("used_bytes"),
                free_bytes=free or None,
                usage_percent=usage or None,
                status=_storage_status(usage) if usage else "unknown",
            )
        )
        total_capacity += total
        total_free += free
    return StorageSummary(
        partitions=partitions,
        count=len(partitions),
        total_capacity_bytes=total_capacity or None,
        total_free_bytes=total_free or None,
    )


def _build_battery_summary(snapshots: dict[str, Any]) -> BatterySummary:
    bat = snapshots.get("battery", {})
    if not bat:
        return BatterySummary()
    return BatterySummary(
        available=bat.get("available"),
        status=bat.get("status"),
        charge_percent=bat.get("percent"),
        plugged_in=bat.get("plugged_in"),
        design_capacity_mwh=bat.get("design_capacity_mwh"),
        full_charge_capacity_mwh=bat.get("full_charge_capacity_mwh"),
        remaining_capacity_mwh=bat.get("remaining_capacity_mwh"),
        health_percent=bat.get("health_percent"),
        wear_percent=bat.get("wear_percent"),
        health_status=bat.get("health_status"),
        cycle_count=bat.get("cycle_count"),
        manufacturer=bat.get("manufacturer"),
        battery_name=bat.get("battery_name"),
        baseline_status="non-baseline",
    )


def _build_findings(finding_rows: list[dict[str, Any]]) -> FindingsGrouped:
    critical, warning, info = [], [], []
    for row in finding_rows:
        fs = FindingSummary(
            finding_id=row.get("finding_id"),
            analyzer=row.get("analyzer", ""),
            severity=row.get("severity", "info"),
            title=row.get("title", ""),
            message=row.get("message", ""),
            evidence=row.get("evidence"),
            recommendation=row.get("recommendation"),
            created_at=row.get("created_at"),
        )
        if fs.severity == "critical":
            critical.append(fs)
        elif fs.severity == "warning":
            warning.append(fs)
        else:
            info.append(fs)
    return FindingsGrouped(
        critical=critical,
        warning=warning,
        info=info,
        critical_count=len(critical),
        warning_count=len(warning),
        info_count=len(info),
    )


def _build_file_analysis_summary(store: SnapshotStore) -> FileAnalysisSummary:
    latest = store.get_latest_file_scan()
    if latest is None:
        return FileAnalysisSummary(available=False)
    stats = latest.get("stats", {})
    return FileAnalysisSummary(
        available=True,
        scan_root=latest.get("scan_root"),
        scan_timestamp=latest.get("completed_at") or latest.get("started_at"),
        files_examined=stats.get("files_examined", 0),
        directories_examined=stats.get("directories_examined", 0),
        bytes_examined=stats.get("bytes_examined", 0),
        files_skipped=stats.get("files_skipped", 0),
        symlinks_skipped=stats.get("symlinks_skipped", 0),
        excluded_items=stats.get("excluded_items", 0),
        inaccessible_items=stats.get("inaccessible_items", 0),
        largest_files=latest.get("large_files", []),
        largest_directories=latest.get("directory_sizes", []),
        file_type_summary=latest.get("file_types", []),
        duplicate_groups=latest.get("duplicate_group_count", 0),
        potential_duplicate_bytes=latest.get("duplicate_bytes_saved", 0),
    )


def _build_remediation_summary() -> RemediationSummary:
    from app.remediation.registry import create_default_registry

    registry = create_default_registry()
    actions = []
    for action in registry.list_actions():
        preview_available = hasattr(action, "preview") or action.action_id == "user_temp_quarantine"
        rollback_available = action.action_id == "user_temp_quarantine"
        real_execution_exists = action.action_id == "user_temp_quarantine"
        actions.append(
            RemediationActionMeta(
                action_id=action.action_id,
                name=action.name,
                risk_level=action.risk_level.value if hasattr(action.risk_level, "value") else str(action.risk_level),
                reversible=action.reversible,
                requires_admin=action.requires_admin,
                preview_available=preview_available,
                rollback_available=rollback_available,
                real_execution_exists=real_execution_exists,
            )
        )
    return RemediationSummary(actions=actions)


def build_health_report(store: SnapshotStore | None = None) -> HealthReport:
    """Build a unified health report from the latest completed discovery run."""
    if store is None:
        store = SnapshotStore()

    errors: list[ReportError] = []

    run = store.get_latest_completed_run()
    if run is None:
        return HealthReport(
            schema_version=SCHEMA_VERSION,
            generated_at=str(__import__("datetime").datetime.now()),
            errors=[
                ReportError(
                    component="discovery",
                    stage="run_lookup",
                    message="No completed discovery run found.",
                    severity="warning",
                )
            ],
        )

    run_id = run["id"]
    analysis_status = run.get("analysis_status")
    snapshots = store.load_snapshots(run_id)

    system = _build_system_info(snapshots)
    storage = _build_storage_summary(snapshots)
    battery = _build_battery_summary(snapshots)

    finding_rows = store.load_findings(run_id)
    findings = _build_findings(finding_rows)

    # Compute findings availability from analysis_status
    if analysis_status in ("completed", "partial"):
        findings_available = True
        findings_count = findings.critical_count + findings.warning_count + findings.info_count
    elif analysis_status == "failed":
        findings_available = False
        findings_count = None
    else:
        # not_run or None (legacy data)
        findings_available = False
        findings_count = None

    sw = snapshots.get("software", {})
    installed_sw = InstalledSoftwareSummary(count=len(sw) if isinstance(sw, list) else 0)

    startup = snapshots.get("startup", {})
    startup_count = len(startup) if isinstance(startup, list) else 0

    procs = snapshots.get("processes", {})
    process_count = len(procs) if isinstance(procs, list) else 0

    svc = snapshots.get("services", {})
    service_count = len(svc) if isinstance(svc, list) else 0

    tasks = snapshots.get("scheduled_tasks", {})
    task_count = len(tasks) if isinstance(tasks, list) else 0

    file_analysis = _build_file_analysis_summary(store)
    remediation = _build_remediation_summary()

    return HealthReport(
        schema_version=SCHEMA_VERSION,
        generated_at=str(__import__("datetime").datetime.now()),
        discovery_run_id=run_id,
        discovery_status=run["status"],
        analysis_status=analysis_status,
        findings_available=findings_available,
        findings_count=findings_count,
        system=system,
        storage=storage,
        battery=battery,
        findings=findings,
        software=installed_sw,
        startup=StartupSummary(count=startup_count),
        processes=ProcessSummary(count=process_count),
        services=ServiceSummary(count=service_count),
        scheduled_tasks=ScheduledTaskSummary(count=task_count),
        file_analysis=file_analysis,
        remediation=remediation,
        errors=errors,
    )
