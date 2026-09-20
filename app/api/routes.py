"""API route definitions."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import get_report, get_store
from app.api.schemas import (
    ActionCandidateResponse,
    ActionCandidatesResponse,
    AdvisoryMetadataResponse,
    AdvisoryResponse,
    AdvisoryHistoricalSummaryResponse,
    BatteryResponse,
    BaselineResponse,
    DataQualityResponse,
    DiagnosticResultResponse,
    DiagnosticsSummaryResponse,
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


@router.get("/remediation/candidates", response_model=ActionCandidatesResponse, tags=["remediation"])
def get_action_candidates_endpoint(
    status: str | None = Query(None, description="Filter by candidate status"),
    action_id: str | None = Query(None, description="Filter by action ID"),
    report: HealthReport = Depends(get_report),
) -> ActionCandidatesResponse:
    """Return action candidates generated by the deterministic policy engine.

    This endpoint does NOT execute, confirm, or rollback any action.
    Candidates are read-only recommendations based on current evidence.
    """
    candidates = report.action_candidates.candidates

    # Apply filters
    if status:
        candidates = [c for c in candidates if c.get("status") == status]
    if action_id:
        candidates = [c for c in candidates if c.get("action_id") == action_id]

    return ActionCandidatesResponse(
        candidates=[
            ActionCandidateResponse(
                candidate_id=c.get("candidate_id", ""),
                action_id=c.get("action_id", ""),
                status=c.get("status", ""),
                title=c.get("title", ""),
                reason=c.get("reason", ""),
                risk_level=c.get("risk_level", ""),
                reversible=c.get("reversible", False),
                executable=c.get("executable", False),
                limitations=c.get("limitations", []),
            )
            for c in candidates
        ],
        available_count=report.action_candidates.available_count,
        proposed_count=report.action_candidates.proposed_count,
        blocked_count=report.action_candidates.blocked_count,
        insufficient_evidence_count=report.action_candidates.insufficient_evidence_count,
        stale_count=report.action_candidates.stale_count,
        total_count=len(candidates),
    )


@router.get("/remediation/candidates/{candidate_id}", response_model=ActionCandidateResponse, tags=["remediation"])
def get_action_candidate_detail_endpoint(
    candidate_id: str,
    report: HealthReport = Depends(get_report),
) -> ActionCandidateResponse:
    """Return a single action candidate by ID."""
    for c in report.action_candidates.candidates:
        if c.get("candidate_id") == candidate_id:
            return ActionCandidateResponse(
                candidate_id=c.get("candidate_id", ""),
                action_id=c.get("action_id", ""),
                status=c.get("status", ""),
                title=c.get("title", ""),
                reason=c.get("reason", ""),
                risk_level=c.get("risk_level", ""),
                reversible=c.get("reversible", False),
                executable=c.get("executable", False),
                limitations=c.get("limitations", []),
            )
    raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found")


@router.get("/remediation/candidates/{candidate_id}/preview", tags=["remediation"])
def get_candidate_preview_endpoint(
    candidate_id: str,
    report: HealthReport = Depends(get_report),
    store: SnapshotStore = Depends(get_store),
) -> dict[str, Any]:
    """Return a read-only preview for an action candidate.

    The preview explains what WOULD happen if the action were executed.
    It does NOT execute, confirm, or create any authorization token.
    """
    from app.remediation.preview import build_preview, PreviewItem
    from app.remediation.candidates import ActionCandidate, CandidateStatus, EvidenceSource, EvidenceSourceType

    # Find the candidate
    candidate_data = None
    for c in report.action_candidates.candidates:
        if c.get("candidate_id") == candidate_id:
            candidate_data = c
            break

    if candidate_data is None:
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found")

    # Reconstruct ActionCandidate from dict
    evidence_list = []
    for ev_dict in candidate_data.get("evidence", []):
        source_type_str = ev_dict.get("source_type", "discovery")
        try:
            source_type = EvidenceSourceType(source_type_str)
        except ValueError:
            source_type = EvidenceSourceType.DISCOVERY
        evidence_list.append(EvidenceSource(
            source_type=source_type,
            source_id=ev_dict.get("source_id", ""),
            observation=ev_dict.get("observation", ""),
        ))

    try:
        status_enum = CandidateStatus(candidate_data.get("status", "unavailable"))
    except ValueError:
        status_enum = CandidateStatus.AVAILABLE

    candidate = ActionCandidate(
        candidate_id=candidate_data.get("candidate_id", ""),
        action_id=candidate_data.get("action_id", ""),
        status=status_enum,
        title=candidate_data.get("title", ""),
        reason=candidate_data.get("reason", ""),
        risk_level=candidate_data.get("risk_level", ""),
        reversible=candidate_data.get("reversible", False),
        requires_admin=candidate_data.get("requires_admin", False),
        limitations=candidate_data.get("limitations", []),
        evidence=evidence_list,
        discovery_run_id=candidate_data.get("discovery_run_id"),
    )

    # Load persisted eligible temp file evidence for preview
    file_analysis_for_preview = None
    temp_evidence = store.get_latest_eligible_temp_evidence()
    if temp_evidence is not None:
        file_analysis_for_preview = {
            "scan_source": temp_evidence.get("scan_root", "unknown"),
            "eligible_temp_files": temp_evidence.get("eligible_files", []),
        }

    preview = build_preview(candidate, file_analysis=file_analysis_for_preview)

    return {
        "preview_id": preview.preview_id,
        "candidate_id": preview.candidate_id,
        "action_id": preview.action_id,
        "generated_at": preview.generated_at,
        "status": preview.status.value,
        "title": preview.title,
        "summary": preview.summary,
        "target": preview.target,
        "affected_count": preview.affected_count,
        "affected_bytes": preview.affected_bytes,
        "affected_items": [
            {"path": item.path, "size_bytes": item.size_bytes, "modified_at": item.modified_at, "fingerprint": item.fingerprint}
            for item in preview.affected_items
        ],
        "expected_effect": preview.expected_effect,
        "side_effects": preview.side_effects,
        "risk_level": preview.risk_level,
        "blast_radius": preview.blast_radius,
        "reversible": preview.reversible,
        "rollback_available": preview.rollback_available,
        "rollback_description": preview.rollback_description,
        "requires_admin": preview.requires_admin,
        "confirmation_required": preview.confirmation_required,
        "evidence": preview.evidence,
        "source_runs": preview.source_runs,
        "freshness_status": preview.freshness_status,
        "limitations": preview.limitations,
        "warnings": preview.warnings,
        "omitted_count": preview.omitted_count,
        "fingerprint": preview.fingerprint,
        "permanent_deletion": preview.permanent_deletion,
        "implementation_status": preview.implementation_status,
        "implementation_status_text": preview.implementation_status_text,
    }


@router.post("/remediation/candidates/{candidate_id}/confirm", tags=["remediation"])
def confirm_candidate_endpoint(
    candidate_id: str,
    body: dict[str, Any] | None = None,
    report: HealthReport = Depends(get_report),
) -> dict[str, Any]:
    """Confirm an action candidate with an existing preview.

    This endpoint creates an explicit human confirmation token.
    It requires a valid candidate and a READY preview.

    The confirmation does NOT execute the action. It is a human
    authorization gate that must be passed before execution.

    Security constraints:
    - Preview must be READY (not stale, not insufficient evidence)
    - Candidate must be AVAILABLE (not proposed/blocked)
    - Confirmation is single-use
    - AI cannot create confirmation tokens
    - No --yes/--force bypass
    """
    from app.remediation.candidates import ActionCandidate, CandidateStatus
    from app.remediation.preview import build_preview, PreviewStatus
    from app.remediation.confirmation_service import (
        ConfirmationService,
        ConfirmationError,
    )

    if body is None:
        body = {}

    preview_id = body.get("preview_id", "")

    if not preview_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="preview_id is required")

    # Find the candidate
    from app.remediation.policy import evaluate_candidates
    policy_context = {}
    candidates = evaluate_candidates(report, policy_context)

    candidate = None
    for c in candidates:
        if c.candidate_id == candidate_id:
            candidate = c
            break

    if candidate is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found")

    # Build the preview to verify it matches
    preview = build_preview(candidate)

    if preview.preview_id != preview_id:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail=f"Preview ID mismatch: expected '{preview.preview_id}', got '{preview_id}'"
        )

    # Attempt confirmation
    service = ConfirmationService()
    try:
        record = service.confirm(candidate, preview)
    except ConfirmationError as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "confirmation_id": record.confirmation_id,
        "candidate_id": record.candidate_id,
        "action_id": record.action_id,
        "preview_id": record.preview_id,
        "preview_fingerprint": record.preview_fingerprint,
        "confirmed_at": record.confirmed_at,
        "consumed": record.consumed,
    }


@router.post("/remediation/candidates/{candidate_id}/execute", tags=["remediation"])
def execute_candidate_endpoint(
    candidate_id: str,
    body: dict[str, Any] | None = None,
    report: HealthReport = Depends(get_report),
) -> dict[str, Any]:
    """Execute a confirmed action candidate through the controlled pipeline.

    This endpoint:
    1. Validates all 14 authorization conditions
    2. Consumes the confirmation token atomically
    3. Revalidates targets (TOCTOU)
    4. Executes through the controlled executor
    5. Records audit transitions
    6. Returns structured result

    Security constraints:
    - Only production actions may execute
    - Confirmation token is consumed atomically
    - Preview must be READY and fresh
    - Action version must match across all components
    - No arbitrary paths, commands, or executables
    """
    from app.remediation.candidates import ActionCandidate, CandidateStatus
    from app.remediation.preview import build_preview, PreviewStatus
    from app.remediation.controlled_execution import (
        ControlledExecutionService,
        ExecutionDeniedError,
    )

    if body is None:
        body = {}

    confirmation_id = body.get("confirmation_id", "")

    if not confirmation_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="confirmation_id is required")

    # Find the candidate
    from app.remediation.policy import evaluate_candidates
    policy_context = {}
    candidates = evaluate_candidates(report, policy_context)

    candidate = None
    for c in candidates:
        if c.candidate_id == candidate_id:
            candidate = c
            break

    if candidate is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Candidate '{candidate_id}' not found")

    # Build the preview
    preview = build_preview(candidate)

    # Execute through controlled pipeline
    service = ControlledExecutionService()
    try:
        result = service.execute(candidate, preview, confirmation_id)
    except ExecutionDeniedError as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "execution_id": result.execution_id,
        "action_id": result.action_id,
        "action_version": result.action_version,
        "candidate_id": candidate_id,
        "confirmation_id": result.confirmation_id,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "status": result.status,
        "files_examined": result.files_examined,
        "files_moved": result.files_moved,
        "files_skipped": result.files_skipped,
        "files_failed": result.files_failed,
        "bytes_moved": result.bytes_moved,
        "quarantine_record_ids": result.quarantine_record_ids,
        "result_summary": result.result_summary,
        "errors": result.errors,
        "rollback_available": result.rollback_available,
    }


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


# ── Diagnostic endpoints (read-only) ─────────────────────────────────────


def _get_diagnostic_results(
    store: SnapshotStore, category: str | None = None
) -> DiagnosticsSummaryResponse:
    """Helper to load the latest diagnostic results."""
    diag_run = store.get_latest_diagnostic_run()
    if diag_run is None:
        return DiagnosticsSummaryResponse()

    run_id = diag_run["id"]
    if category:
        results = store.get_diagnostic_results_by_category(run_id, category)
    else:
        results = store.load_diagnostic_results(run_id)

    categories = sorted(set(r.get("category", "") for r in results if r.get("category")))
    status_counts: dict[str, int] = {}
    for r in results:
        s = r.get("status", "unknown")
        status_counts[s] = status_counts.get(s, 0) + 1

    return DiagnosticsSummaryResponse(
        available=True,
        run_id=run_id,
        status=diag_run.get("status"),
        result_count=len(results),
        categories=categories,
        status_counts=status_counts,
        results=[
            DiagnosticResultResponse(
                diagnostic_id=r["diagnostic_id"],
                category=r["category"],
                status=r["status"],
                title=r["title"],
                summary=r["summary"],
                evidence=r.get("evidence", {}),
                source=r.get("source", ""),
                collected_at=r.get("collected_at", ""),
                collection_time_ms=r.get("collection_time_ms", 0),
                limitations=r.get("limitations", []),
                errors=r.get("errors", []),
            )
            for r in results
        ],
    )


@router.get("/diagnostics/summary", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_summary(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return all diagnostic results from the latest diagnostic run."""
    return _get_diagnostic_results(store)


@router.get("/diagnostics/disk", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_disk(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return disk health diagnostic results."""
    return _get_diagnostic_results(store, category="disk")


@router.get("/diagnostics/thermal", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_thermal(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return thermal diagnostic results."""
    return _get_diagnostic_results(store, category="thermal")


@router.get("/diagnostics/performance", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_performance(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return performance diagnostic results."""
    return _get_diagnostic_results(store, category="performance")


@router.get("/diagnostics/devices", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_devices(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return device/driver diagnostic results."""
    return _get_diagnostic_results(store, category="devices")


@router.get("/diagnostics/windows", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_windows(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return Windows health diagnostic results."""
    return _get_diagnostic_results(store, category="windows")


@router.get("/diagnostics/event-log", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_event_log(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return event log diagnostic results."""
    return _get_diagnostic_results(store, category="event_log")


@router.get("/diagnostics/reliability", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_reliability(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return reliability/crash-history diagnostic results."""
    return _get_diagnostic_results(store, category="reliability")


@router.get("/diagnostics/boot-timing", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_boot_timing(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return boot/startup timing diagnostic results."""
    return _get_diagnostic_results(store, category="boot_timing")


@router.get("/diagnostics/network-health", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_network_health(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return network health diagnostic results."""
    return _get_diagnostic_results(store, category="network_health")


@router.get("/diagnostics/driver-consistency", response_model=DiagnosticsSummaryResponse, tags=["diagnostics"])
def get_diagnostics_driver_consistency(
    store: SnapshotStore = Depends(get_store),
) -> DiagnosticsSummaryResponse:
    """Return driver consistency diagnostic results."""
    return _get_diagnostic_results(store, category="driver_consistency")
