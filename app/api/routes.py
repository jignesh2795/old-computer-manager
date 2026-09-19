"""API route definitions."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import get_report, get_store
from app.api.schemas import (
    AdvisoryMetadataResponse,
    AdvisoryResponse,
    AdvisoryHistoricalSummaryResponse,
    BatteryResponse,
    BaselineResponse,
    DataQualityResponse,
    ErrorResponse,
    FileAnalysisResponse,
    FindingResponse,
    FindingsResponse,
    HistorySummaryResponse,
    LimitationResponse,
    ObservationResponse,
    AnomalyResponse,
    RecommendationResponse,
    RecurringFindingResponse,
    RemediationActionResponse,
    RemediationActionsResponse,
    ReportResponse,
    StoragePartitionResponse,
    StorageResponse,
    SystemResponse,
    TrendResponse,
    UncertaintyResponse,
)
from app.reporting.models import HealthReport

router = APIRouter(prefix="/api/v1")


def _report_to_report_response(report: Any) -> ReportResponse:
    """Convert a HealthReport dataclass to a ReportResponse pydantic model."""
    return ReportResponse(
        schema_version=report.schema_version,
        generated_at=report.generated_at,
        discovery_run_id=report.discovery_run_id,
        discovery_status=report.discovery_status,
        analysis_status=report.analysis_status,
        findings_available=report.findings_available,
        findings_count=report.findings_count,
        system=SystemResponse(
            hostname=report.system.hostname,
            os_name=report.system.os_name,
            os_version=report.system.os_version,
            architecture=report.system.architecture,
            manufacturer=report.system.manufacturer,
            model=report.system.model,
            bios_vendor=report.system.bios_vendor,
            bios_version=report.system.bios_version,
            cpu_name=report.system.cpu_name,
            cpu_cores_physical=report.system.cpu_cores_physical,
            cpu_cores_logical=report.system.cpu_cores_logical,
            ram_total_bytes=report.system.ram_total_bytes,
        ),
        storage=StorageResponse(
            partitions=[
                StoragePartitionResponse(
                    device=p.device,
                    filesystem=p.filesystem,
                    total_bytes=p.total_bytes,
                    used_bytes=p.used_bytes,
                    free_bytes=p.free_bytes,
                    usage_percent=p.usage_percent,
                    status=p.status,
                )
                for p in report.storage.partitions
            ],
            count=report.storage.count,
            total_capacity_bytes=report.storage.total_capacity_bytes,
            total_free_bytes=report.storage.total_free_bytes,
        ),
        battery=BatteryResponse(
            available=report.battery.available,
            status=report.battery.status,
            charge_percent=report.battery.charge_percent,
            plugged_in=report.battery.plugged_in,
            design_capacity_mwh=report.battery.design_capacity_mwh,
            full_charge_capacity_mwh=report.battery.full_charge_capacity_mwh,
            remaining_capacity_mwh=report.battery.remaining_capacity_mwh,
            health_percent=report.battery.health_percent,
            wear_percent=report.battery.wear_percent,
            health_status=report.battery.health_status,
            cycle_count=report.battery.cycle_count,
            manufacturer=report.battery.manufacturer,
            battery_name=report.battery.battery_name,
            baseline_status=report.battery.baseline_status,
        ),
        findings=FindingsResponse(
            analysis_status=report.analysis_status,
            findings_available=report.findings_available,
            findings_count=report.findings_count,
            critical_count=report.findings.critical_count,
            warning_count=report.findings.warning_count,
            info_count=report.findings.info_count,
            findings=[
                FindingResponse(
                    finding_id=f.finding_id,
                    analyzer=f.analyzer,
                    severity=f.severity,
                    title=f.title,
                    message=f.message,
                    evidence=f.evidence,
                    recommendation=f.recommendation,
                    created_at=f.created_at,
                )
                for f in (
                    report.findings.critical + report.findings.warning + report.findings.info
                )
            ],
        ),
        software={"count": report.software.count},
        startup={"count": report.startup.count},
        processes={"count": report.processes.count},
        services={"count": report.services.count},
        scheduled_tasks={"count": report.scheduled_tasks.count},
        file_analysis=FileAnalysisResponse(
            available=report.file_analysis.available,
            scan_root=report.file_analysis.scan_root,
            scan_timestamp=report.file_analysis.scan_timestamp,
            files_examined=report.file_analysis.files_examined,
            directories_examined=report.file_analysis.directories_examined,
            bytes_examined=report.file_analysis.bytes_examined,
            files_skipped=report.file_analysis.files_skipped,
            symlinks_skipped=report.file_analysis.symlinks_skipped,
            excluded_items=report.file_analysis.excluded_items,
            inaccessible_items=report.file_analysis.inaccessible_items,
            largest_files=report.file_analysis.largest_files,
            largest_directories=report.file_analysis.largest_directories,
            file_type_summary=report.file_analysis.file_type_summary,
            duplicate_groups=report.file_analysis.duplicate_groups,
            potential_duplicate_bytes=report.file_analysis.potential_duplicate_bytes,
        ),
        remediation=RemediationActionsResponse(
            actions=[
                RemediationActionResponse(
                    action_id=a.action_id,
                    name=a.name,
                    risk_level=a.risk_level,
                    reversible=a.reversible,
                    requires_admin=a.requires_admin,
                    preview_available=a.preview_available,
                    rollback_available=a.rollback_available,
                    real_execution_exists=a.real_execution_exists,
                    implementation_status=a.implementation_status,
                    blast_radius=a.blast_radius,
                    rollback_category=a.rollback_category,
                    eligibility=a.eligibility,
                    category=a.category,
                    action_version=a.action_version,
                )
                for a in report.remediation.actions
            ],
            count=len(report.remediation.actions),
        ),
        errors=[
            {"component": e.component, "stage": e.stage, "message": e.message, "severity": e.severity}
            for e in report.errors
        ],
    )


@router.get("/report", response_model=ReportResponse, tags=["report"])
def get_report_endpoint(report: HealthReport = Depends(get_report)) -> ReportResponse:
    """Return the full unified health report as JSON.

    This reads existing database data and does not trigger
    any discovery, analysis, or filesystem operations.
    """
    return _report_to_report_response(report)


@router.get("/findings", response_model=FindingsResponse, tags=["findings"])
def get_findings_endpoint(
    severity: str | None = Query(None, description="Filter by severity: critical, warning, info"),
    analyzer: str | None = Query(None, description="Filter by analyzer name"),
    report: HealthReport = Depends(get_report),
) -> FindingsResponse:
    """Return findings from the latest analysis, with optional filtering."""

    all_findings = (
        report.findings.critical + report.findings.warning + report.findings.info
    )

    if severity:
        valid_severities = {"critical", "warning", "info"}
        if severity not in valid_severities:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid severity '{severity}'. Must be one of: {sorted(valid_severities)}",
            )
        all_findings = [f for f in all_findings if f.severity == severity]

    if analyzer:
        all_findings = [f for f in all_findings if f.analyzer == analyzer]

    return FindingsResponse(
        analysis_status=report.analysis_status,
        findings_available=report.findings_available,
        findings_count=report.findings_count,
        critical_count=sum(1 for f in all_findings if f.severity == "critical"),
        warning_count=sum(1 for f in all_findings if f.severity == "warning"),
        info_count=sum(1 for f in all_findings if f.severity == "info"),
        findings=[
            FindingResponse(
                finding_id=f.finding_id,
                analyzer=f.analyzer,
                severity=f.severity,
                title=f.title,
                message=f.message,
                evidence=f.evidence,
                recommendation=f.recommendation,
                created_at=f.created_at,
            )
            for f in all_findings
        ],
    )


@router.get("/storage", response_model=StorageResponse, tags=["storage"])
def get_storage_endpoint(report: HealthReport = Depends(get_report)) -> StorageResponse:
    """Return the storage summary from the latest discovery."""
    return StorageResponse(
        partitions=[
            StoragePartitionResponse(
                device=p.device,
                filesystem=p.filesystem,
                total_bytes=p.total_bytes,
                used_bytes=p.used_bytes,
                free_bytes=p.free_bytes,
                usage_percent=p.usage_percent,
                status=p.status,
            )
            for p in report.storage.partitions
        ],
        count=report.storage.count,
        total_capacity_bytes=report.storage.total_capacity_bytes,
        total_free_bytes=report.storage.total_free_bytes,
    )


@router.get("/battery", response_model=BatteryResponse, tags=["battery"])
def get_battery_endpoint(report: HealthReport = Depends(get_report)) -> BatteryResponse:
    """Return the battery section from the latest discovery.

    No battery serial number is exposed.
    """
    return BatteryResponse(
        available=report.battery.available,
        status=report.battery.status,
        charge_percent=report.battery.charge_percent,
        plugged_in=report.battery.plugged_in,
        design_capacity_mwh=report.battery.design_capacity_mwh,
        full_charge_capacity_mwh=report.battery.full_charge_capacity_mwh,
        remaining_capacity_mwh=report.battery.remaining_capacity_mwh,
        health_percent=report.battery.health_percent,
        wear_percent=report.battery.wear_percent,
        health_status=report.battery.health_status,
        cycle_count=report.battery.cycle_count,
        manufacturer=report.battery.manufacturer,
        battery_name=report.battery.battery_name,
        baseline_status=report.battery.baseline_status,
    )


@router.get("/file-analysis", response_model=FileAnalysisResponse, tags=["file-analysis"])
def get_file_analysis_endpoint(report: HealthReport = Depends(get_report)) -> FileAnalysisResponse:
    """Return the latest file-analysis summary from the database."""
    return FileAnalysisResponse(
        available=report.file_analysis.available,
        scan_root=report.file_analysis.scan_root,
        scan_timestamp=report.file_analysis.scan_timestamp,
        files_examined=report.file_analysis.files_examined,
        directories_examined=report.file_analysis.directories_examined,
        bytes_examined=report.file_analysis.bytes_examined,
        files_skipped=report.file_analysis.files_skipped,
        symlinks_skipped=report.file_analysis.symlinks_skipped,
        excluded_items=report.file_analysis.excluded_items,
        inaccessible_items=report.file_analysis.inaccessible_items,
        largest_files=report.file_analysis.largest_files,
        largest_directories=report.file_analysis.largest_directories,
        file_type_summary=report.file_analysis.file_type_summary,
        duplicate_groups=report.file_analysis.duplicate_groups,
        potential_duplicate_bytes=report.file_analysis.potential_duplicate_bytes,
    )


@router.get("/remediation/actions", response_model=RemediationActionsResponse, tags=["remediation"])
def get_remediation_actions_endpoint(report: HealthReport = Depends(get_report)) -> RemediationActionsResponse:
    """Return remediation action metadata only.

    This endpoint does NOT execute, preview, confirm, or rollback any action.
    """
    return RemediationActionsResponse(
        actions=[
            RemediationActionResponse(
                action_id=a.action_id,
                name=a.name,
                risk_level=a.risk_level,
                reversible=a.reversible,
                requires_admin=a.requires_admin,
                preview_available=a.preview_available,
                rollback_available=a.rollback_available,
                real_execution_exists=a.real_execution_exists,
                implementation_status=a.implementation_status,
                blast_radius=a.blast_radius,
                rollback_category=a.rollback_category,
                eligibility=a.eligibility,
                category=a.category,
                action_version=a.action_version,
            )
            for a in report.remediation.actions
        ],
        count=len(report.remediation.actions),
    )


@router.get("/system", response_model=SystemResponse, tags=["system"])
def get_system_endpoint(report: HealthReport = Depends(get_report)) -> SystemResponse:
    """Return the system section from the latest discovery."""
    return SystemResponse(
        hostname=report.system.hostname,
        os_name=report.system.os_name,
        os_version=report.system.os_version,
        architecture=report.system.architecture,
        manufacturer=report.system.manufacturer,
        model=report.system.model,
        bios_vendor=report.system.bios_vendor,
        bios_version=report.system.bios_version,
        cpu_name=report.system.cpu_name,
        cpu_cores_physical=report.system.cpu_cores_physical,
        cpu_cores_logical=report.system.cpu_cores_logical,
        ram_total_bytes=report.system.ram_total_bytes,
    )


@router.get("/ai/advisory", response_model=AdvisoryResponse, tags=["ai"])
def get_ai_advisory_endpoint(report: HealthReport = Depends(get_report)) -> AdvisoryResponse:
    """Return AI advisory for the latest report.

    This endpoint generates advisory using the deterministic mock provider.
    It does NOT execute remediation or modify the system.
    """
    from app.ai.advisory import generate_advisory, AdvisoryError
    from app.ai.provider import MockProvider

    # Use mock provider for API (no external calls)
    provider = MockProvider()

    try:
        advisory = generate_advisory(report, provider)
    except AdvisoryError:
        # Return empty advisory on error
        return AdvisoryResponse(
            summary="Advisory generation failed",
            observations=[],
            recommendations=[],
            uncertainties=[],
            limitations=[],
        )

    return AdvisoryResponse(
        schema_version=advisory.schema_version,
        generated_at=advisory.generated_at,
        report_run_id=advisory.report_run_id,
        analysis_status=advisory.analysis_status,
        summary=advisory.summary,
        observations=[
            ObservationResponse(
                title=obs.title,
                evidence=obs.evidence,
                source=obs.source,
                severity=obs.severity,
                confidence=obs.confidence,
            )
            for obs in advisory.observations
        ],
        recommendations=[
            RecommendationResponse(
                title=rec.title,
                rationale=rec.rationale,
                related_finding_ids=rec.related_finding_ids,
                related_action_ids=rec.related_action_ids,
                risk_level=rec.risk_level,
                requires_confirmation=rec.requires_confirmation,
                executable=rec.executable,
            )
            for rec in advisory.recommendations
        ],
        uncertainties=[
            UncertaintyResponse(
                description=unc.description,
                impact=unc.impact,
            )
            for unc in advisory.uncertainties
        ],
        limitations=[
            LimitationResponse(description=lim.description)
            for lim in advisory.limitations
        ],
        metadata=AdvisoryMetadataResponse(
            provider=advisory.metadata.provider,
            model=advisory.metadata.model,
            prompt_version=advisory.metadata.prompt_version,
            generated_at=advisory.metadata.generated_at,
        ),
        historical_summary=(
            AdvisoryHistoricalSummaryResponse(
                runs_considered=advisory.historical_summary.runs_considered,
                observations_used=advisory.historical_summary.observations_used,
                trends_count=advisory.historical_summary.trends_count,
                baselines_established=advisory.historical_summary.baselines_established,
                recurring_findings_count=advisory.historical_summary.recurring_findings_count,
                anomalies_count=advisory.historical_summary.anomalies_count,
                data_quality_issues=advisory.historical_summary.data_quality_issues,
                limited_by=advisory.historical_summary.limited_by,
            )
            if advisory.historical_summary is not None
            else None
        ),
    )


# -- Historical analysis endpoints -------------------------------------------


@router.get("/history/summary", response_model=HistorySummaryResponse, tags=["history"])
def get_history_summary(
    limit: int | None = Query(None, description="Maximum number of runs to consider"),
    metric: str | None = Query(None, description="Filter to specific metric"),
    store: SnapshotStore = Depends(get_store),
) -> HistorySummaryResponse:
    """Return historical analysis summary with trends, baselines, and anomalies.

    This endpoint analyzes existing discovery run data. It does not
    trigger any new discovery, analysis, or filesystem operations.
    """
    from app.history.runner import run_history

    summary = run_history(store, limit=limit, metric=metric)

    return HistorySummaryResponse(
        runs_considered=summary.runs_considered,
        observations_available=summary.observations_available,
        run_ids=list(summary.run_ids),
        trends=[
            TrendResponse(
                metric_name=t.metric_name,
                observations_count=t.observations_count,
                first_value=t.first_value,
                latest_value=t.latest_value,
                minimum=t.minimum,
                maximum=t.maximum,
                delta_absolute=t.delta_absolute,
                delta_percent=t.delta_percent,
                direction=t.direction.value,
                first_timestamp=t.first_timestamp,
                latest_timestamp=t.latest_timestamp,
            )
            for t in summary.trends
        ],
        baseline=[
            BaselineResponse(
                metric_name=b.metric_name,
                baseline_run_id=b.baseline_run_id,
                baseline_timestamp=b.baseline_timestamp,
                baseline_value=b.baseline_value,
                current_value=b.current_value,
                delta=b.delta,
                delta_percent=b.delta_percent,
                baseline_status=b.baseline_status.value,
            )
            for b in summary.baseline
        ],
        recurring_findings=[
            RecurringFindingResponse(
                analyzer=r.analyzer,
                severity=r.severity,
                title=r.title,
                first_seen=r.first_seen,
                last_seen=r.last_seen,
                occurrence_count=r.occurrence_count,
                run_ids=list(r.run_ids),
            )
            for r in summary.recurring_findings
        ],
        anomalies=[
            AnomalyResponse(
                metric_name=a.metric_name,
                severity=a.severity,
                title=a.title,
                message=a.message,
                evidence=a.evidence,
                first_detected=a.first_detected,
                last_detected=a.last_detected,
                occurrence_count=a.occurrence_count,
            )
            for a in summary.anomalies
        ],
        data_quality=[
            DataQualityResponse(
                metric_name=d.metric_name,
                total_observations=d.total_observations,
                valid_observations=d.valid_observations,
                missing_count=d.missing_count,
                not_supported_count=d.not_supported_count,
                failed_count=d.failed_count,
            )
            for d in summary.data_quality
        ],
    )


@router.get("/history/trends", response_model=list[TrendResponse], tags=["history"])
def get_history_trends(
    limit: int | None = Query(None, description="Maximum number of runs to consider"),
    metric: str | None = Query(None, description="Filter to specific metric"),
    store: SnapshotStore = Depends(get_store),
) -> list[TrendResponse]:
    """Return trend analysis for historical metrics.

    This endpoint analyzes existing discovery run data.
    """
    from app.history.runner import run_history

    summary = run_history(store, limit=limit, metric=metric)

    return [
        TrendResponse(
            metric_name=t.metric_name,
            observations_count=t.observations_count,
            first_value=t.first_value,
            latest_value=t.latest_value,
            minimum=t.minimum,
            maximum=t.maximum,
            delta_absolute=t.delta_absolute,
            delta_percent=t.delta_percent,
            direction=t.direction.value,
            first_timestamp=t.first_timestamp,
            latest_timestamp=t.latest_timestamp,
        )
        for t in summary.trends
    ]


@router.get("/history/baseline", response_model=list[BaselineResponse], tags=["history"])
def get_history_baseline(
    limit: int | None = Query(None, description="Maximum number of runs to consider"),
    metric: str | None = Query(None, description="Filter to specific metric"),
    store: SnapshotStore = Depends(get_store),
) -> list[BaselineResponse]:
    """Return baseline comparison for historical metrics.

    This endpoint analyzes existing discovery run data.
    """
    from app.history.runner import run_history

    summary = run_history(store, limit=limit, metric=metric)

    return [
        BaselineResponse(
            metric_name=b.metric_name,
            baseline_run_id=b.baseline_run_id,
            baseline_timestamp=b.baseline_timestamp,
            baseline_value=b.baseline_value,
            current_value=b.current_value,
            delta=b.delta,
            delta_percent=b.delta_percent,
            baseline_status=b.baseline_status.value,
        )
        for b in summary.baseline
    ]


@router.get("/history/anomalies", response_model=list[AnomalyResponse], tags=["history"])
def get_history_anomalies(
    limit: int | None = Query(None, description="Maximum number of runs to consider"),
    metric: str | None = Query(None, description="Filter to specific metric"),
    store: SnapshotStore = Depends(get_store),
) -> list[AnomalyResponse]:
    """Return detected anomalies in historical data.

    This endpoint analyzes existing discovery run data.
    """
    from app.history.runner import run_history

    summary = run_history(store, limit=limit, metric=metric)

    return [
        AnomalyResponse(
            metric_name=a.metric_name,
            severity=a.severity,
            title=a.title,
            message=a.message,
            evidence=a.evidence,
            first_detected=a.first_detected,
            last_detected=a.last_detected,
            occurrence_count=a.occurrence_count,
        )
        for a in summary.anomalies
    ]
