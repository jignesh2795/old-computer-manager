"""Build a unified HealthReport from existing database data."""

from __future__ import annotations

import json
from typing import Any

from app.analyzers.constants import STORAGE_CRITICAL_THRESHOLD, STORAGE_WARNING_THRESHOLD
from app.database.sqlite import SnapshotStore
from app.reporting.models import (
    ActionCandidateSummary,
    BatterySummary,
    DiagnosticsSummary,
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
    scan_id = latest.get("id")
    # Load child table data
    large_files = []
    file_type_summary = []
    duplicate_group_count = 0
    if scan_id is not None:
        large_files = store.load_file_scan_large_files(scan_id)
        file_type_summary = store.load_file_scan_type_groups(scan_id)
        duplicate_groups = store.load_file_scan_duplicate_groups(scan_id)
        duplicate_group_count = len(duplicate_groups)
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
        largest_files=large_files,
        largest_directories=[],
        file_type_summary=file_type_summary,
        duplicate_groups=duplicate_group_count,
        potential_duplicate_bytes=0,
    )


def _build_diagnostics_summary(store: SnapshotStore | None = None) -> DiagnosticsSummary:
    """Build diagnostics summary from the latest diagnostic run."""
    if store is None:
        return DiagnosticsSummary()

    try:
        diag_run = store.get_latest_diagnostic_run()
    except Exception:
        return DiagnosticsSummary()

    if diag_run is None:
        return DiagnosticsSummary()

    try:
        results = store.load_diagnostic_results(diag_run["id"])
    except Exception:
        return DiagnosticsSummary(available=True, run_id=diag_run["id"], status=diag_run.get("status"))

    categories = sorted(set(r.get("category", "") for r in results if r.get("category")))
    status_counts: dict[str, int] = {}
    for r in results:
        s = r.get("status", "unknown")
        status_counts[s] = status_counts.get(s, 0) + 1

    return DiagnosticsSummary(
        available=True,
        run_id=diag_run["id"],
        status=diag_run.get("status"),
        result_count=len(results),
        categories=categories,
        status_counts=status_counts,
        results=results,
    )


def _build_remediation_summary() -> RemediationSummary:
    from app.remediation.registry import create_default_registry

    registry = create_default_registry()
    _REAL_ACTIONS = {"user_temp_quarantine", "disk.cleanup_temp"}
    actions = []
    for action in registry.list_actions():
        is_real = action.action_id in _REAL_ACTIONS
        preview_available = hasattr(action, "preview") or is_real
        rollback_available = is_real
        real_execution_exists = is_real
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
                implementation_status=action.implementation_status.value,
                blast_radius=action.blast_radius.value,
                rollback_category=action.rollback_category.value,
                eligibility=action.eligibility.value,
                category=action.category,
                action_version=action.action_version,
            )
        )
    return RemediationSummary(actions=actions)


def _build_action_candidates_summary(
    storage: StorageSummary,
    file_analysis: FileAnalysisSummary,
    findings: FindingsGrouped,
    discovery_run_id: int | None,
    store: SnapshotStore | None = None,
) -> ActionCandidateSummary:
    """Build action candidates from current report data using the policy engine."""
    from app.remediation.candidates import CandidateStatus
    from app.remediation.policy import PolicyContext, evaluate_candidates

    # Build policy context from current report data
    storage_dict = {
        "partitions": [
            {
                "device": p.device or "",
                "usage_percent": p.usage_percent or 0,
            }
            for p in storage.partitions
        ]
    }

    file_analysis_dict: dict[str, Any] = {}
    if file_analysis.available:
        file_analysis_dict = {
            "scan_source": file_analysis.scan_root or "unknown",
        }
        # Load persisted eligible temp file evidence from the store
        eligible_temp_files: list[dict[str, Any]] = []
        if store is not None:
            try:
                temp_evidence = store.get_latest_eligible_temp_evidence()
                if temp_evidence is not None:
                    eligible_temp_files = temp_evidence.get("eligible_files", [])
            except Exception:
                pass
        file_analysis_dict["eligible_temp_files"] = eligible_temp_files

    findings_list = []
    for f in findings.critical + findings.warning:
        findings_list.append({
            "id": f.finding_id,
            "severity": f.severity,
            "title": f.title,
        })

    ctx = PolicyContext(
        discovery_run_id=discovery_run_id,
        storage_summary=storage_dict,
        file_analysis=file_analysis_dict if file_analysis_dict else None,
        findings=findings_list if findings_list else None,
    )

    result = evaluate_candidates(ctx)

    return ActionCandidateSummary(
        available_count=result.available_count,
        proposed_count=result.proposed_count,
        blocked_count=result.blocked_count,
        insufficient_evidence_count=result.insufficient_evidence_count,
        stale_count=result.stale_count,
        total_count=result.total_count,
        candidates=[
            {
                "candidate_id": c.candidate_id,
                "action_id": c.action_id,
                "status": c.status.value,
                "title": c.title,
                "reason": c.reason,
                "risk_level": c.risk_level,
                "reversible": c.reversible,
                "executable": c.executable,
                "limitations": c.limitations,
            }
            for c in result.candidates
        ],
    )


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
    diagnostics = _build_diagnostics_summary(store)
    action_candidates = _build_action_candidates_summary(
        storage, file_analysis, findings, run_id, store=store,
    )

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
        action_candidates=action_candidates,
        diagnostics=diagnostics,
        errors=errors,
    )
