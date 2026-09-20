"""Action Policy Engine — deterministic candidate generation.

Maps structured evidence to candidate actions.  The policy layer
decides whether a candidate is available; the AI explains it;
the human confirms; only then can execution occur.

SAFETY: This module must NOT import or instantiate an executor.
It must NOT have filesystem mutation authority.
It must NOT call subprocess or shell.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.remediation.action import ImplementationStatus
from app.remediation.candidates import (
    ActionCandidate,
    CandidateStatus,
    CandidatesSummary,
    EvidenceSource,
    EvidenceSourceType,
)
from app.remediation.catalog import CATALOG, ActionCatalogEntry, get_catalog_entry
from app.remediation.eligibility import check_eligibility

# ── Limits ──────────────────────────────────────────────────────────
MAX_ACTION_CANDIDATES = 20
MAX_EVIDENCE_ITEMS = 10

# ── Freshness windows ──────────────────────────────────────────────
# How long evidence is considered "fresh" for each action category
FRESHNESS_WINDOWS: dict[str, int] = {
    "cleanup": 7,       # days — file-based cleanup needs recent scan
    "diagnostic": 1,    # days — diagnostic data goes stale quickly
}


@dataclass(frozen=True)
class PolicyContext:
    """Current system state for candidate evaluation.

    All fields are read-only snapshots.  The policy engine does NOT
    re-run scans or diagnostics to fill missing data.
    """
    discovery_run_id: int | None = None
    discovery_completed_at: str = ""
    storage_summary: dict[str, Any] | None = None
    file_analysis: dict[str, Any] | None = None
    findings: list[dict[str, Any]] | None = None
    diagnostics: dict[str, Any] | None = None
    historical: dict[str, Any] | None = None


def _catalog_to_candidate_status(
    entry: ActionCatalogEntry,
) -> CandidateStatus:
    """Map catalog implementation status to candidate status."""
    if entry.implementation_status == ImplementationStatus.IMPLEMENTED:
        return CandidateStatus.AVAILABLE
    if entry.implementation_status == ImplementationStatus.PROPOSED:
        return CandidateStatus.PROPOSED
    if entry.implementation_status == ImplementationStatus.BLOCKED:
        return CandidateStatus.BLOCKED
    return CandidateStatus.INSUFFICIENT_EVIDENCE


def _build_storage_evidence(
    ctx: PolicyContext,
) -> list[EvidenceSource]:
    """Extract storage pressure evidence from context."""
    evidence: list[EvidenceSource] = []
    storage = ctx.storage_summary
    if not storage:
        return evidence

    partitions = storage.get("partitions", [])
    for p in partitions:
        usage = p.get("usage_percent", 0)
        if usage and usage >= 80:
            evidence.append(EvidenceSource(
                source_type=EvidenceSourceType.DISCOVERY,
                source_id=f"storage:{p.get('device', 'unknown')}",
                observation=f"Storage {p.get('device', '?')} is {usage}% full",
                value=usage,
                interpretation="high" if usage < 90 else "critical",
            ))
    return evidence


def _build_file_analysis_evidence(
    ctx: PolicyContext,
) -> list[EvidenceSource]:
    """Extract temp file evidence from file analysis."""
    evidence: list[EvidenceSource] = []
    fa = ctx.file_analysis
    if not fa:
        return evidence

    eligible_temp = fa.get("eligible_temp_files", [])
    if eligible_temp:
        total_bytes = sum(f.get("size_bytes", 0) for f in eligible_temp)
        evidence.append(EvidenceSource(
            source_type=EvidenceSourceType.FILE_ANALYSIS,
            source_id=f"file_analysis:temp:{len(eligible_temp)}",
            observation=f"{len(eligible_temp)} eligible temp files totaling {total_bytes} bytes",
            value={"count": len(eligible_temp), "total_bytes": total_bytes},
            interpretation="eligible cleanup candidates exist",
        ))
    return evidence


def _build_finding_evidence(
    ctx: PolicyContext,
) -> list[EvidenceSource]:
    """Extract relevant findings as evidence."""
    evidence: list[EvidenceSource] = []
    findings = ctx.findings or []
    for f in findings:
        severity = f.get("severity", "")
        title = f.get("title", "")
        if severity == "critical" and "disk" in title.lower():
            evidence.append(EvidenceSource(
                source_type=EvidenceSourceType.FINDING,
                source_id=f"finding:{f.get('id', '?')}",
                observation=f"Critical finding: {title}",
                value=severity,
                interpretation="storage pressure from findings",
            ))
    return evidence


def _evaluate_cleanup_temp(
    ctx: PolicyContext,
    entry: ActionCatalogEntry,
) -> ActionCandidate | None:
    """Rule A: Storage pressure + eligible old user-temp files → disk.cleanup_temp.

    Required evidence:
    - storage usage warning OR critical
    - valid file-analysis/temp evidence
    - eligible candidate files exist
    - action is implemented
    - action eligibility is valid
    """
    storage_evidence = _build_storage_evidence(ctx)
    file_evidence = _build_file_analysis_evidence(ctx)
    finding_evidence = _build_finding_evidence(ctx)

    all_evidence = storage_evidence + file_evidence + finding_evidence

    # Check if storage pressure exists
    has_storage_pressure = any(
        e.interpretation in ("high", "critical") for e in storage_evidence
    )

    # Check if eligible temp files exist
    has_eligible_files = any(
        e.source_type == EvidenceSourceType.FILE_ANALYSIS for e in file_evidence
    )

    # Determine status
    if has_storage_pressure and has_eligible_files:
        status = CandidateStatus.AVAILABLE
        reason = "Storage pressure detected with eligible cleanup candidates."
    elif has_storage_pressure and not has_eligible_files:
        status = CandidateStatus.INSUFFICIENT_EVIDENCE
        reason = (
            "Storage pressure detected, but no eligible cleanup candidates "
            "have been established by the available file analysis."
        )
    else:
        return None  # No evidence for this rule

    # Get file details for the candidate
    file_details = {}
    if ctx.file_analysis:
        eligible = ctx.file_analysis.get("eligible_temp_files", [])
        if eligible:
            total_bytes = sum(f.get("size_bytes", 0) for f in eligible)
            file_details = {
                "eligible_file_count": len(eligible),
                "total_bytes": total_bytes,
                "scan_source": ctx.file_analysis.get("scan_source", "unknown"),
                "scan_run_id": ctx.file_analysis.get("scan_run_id"),
            }

    limitations = []
    if not has_eligible_files:
        limitations.append("No eligible temp file data available from file analysis.")

    return ActionCandidate(
        candidate_id="disk.cleanup_temp",
        action_id="disk.cleanup_temp",
        status=status,
        title="Safe temp cleanup (quarantine)",
        reason=reason,
        evidence=all_evidence[:MAX_EVIDENCE_ITEMS],
        discovery_run_id=ctx.discovery_run_id,
        confidence_basis="deterministic_policy",
        eligibility_status=entry.eligibility.value,
        implementation_status=entry.implementation_status.value,
        risk_level=entry.risk_level.value,
        blast_radius=entry.blast_radius.value,
        reversible=entry.reversible,
        requires_admin=entry.requires_admin,
        preview_available=True,
        rollback_available=True,
        limitations=limitations,
        stale_after="7 days from file analysis scan",
    )


def _evaluate_user_temp_quarantine(
    ctx: PolicyContext,
    entry: ActionCatalogEntry,
) -> ActionCandidate | None:
    """Rule B: Direct request/evidence for user-temp quarantine.

    Use only when actual eligible temp-file evidence exists.
    Do not generate a candidate merely because the action exists.
    """
    file_evidence = _build_file_analysis_evidence(ctx)

    has_eligible_files = len(file_evidence) > 0

    if not has_eligible_files:
        return None  # No evidence — do not generate candidate

    status = CandidateStatus.AVAILABLE
    reason = "Eligible old temp files detected in user directory."

    limitations = []
    scan_source = "unknown"
    scan_run_id = None
    if ctx.file_analysis:
        scan_source = ctx.file_analysis.get("scan_source", "unknown")
        scan_run_id = ctx.file_analysis.get("scan_run_id")
        eligible = ctx.file_analysis.get("eligible_temp_files", [])
        if not eligible:
            limitations.append("No eligible temp file data available.")

    return ActionCandidate(
        candidate_id="user_temp_quarantine",
        action_id="user_temp_quarantine",
        status=status,
        title="Quarantine old temporary files",
        reason=reason,
        evidence=file_evidence[:MAX_EVIDENCE_ITEMS],
        discovery_run_id=ctx.discovery_run_id,
        confidence_basis="deterministic_policy",
        eligibility_status=entry.eligibility.value,
        implementation_status=entry.implementation_status.value,
        risk_level=entry.risk_level.value,
        blast_radius=entry.blast_radius.value,
        reversible=entry.reversible,
        requires_admin=entry.requires_admin,
        preview_available=True,
        rollback_available=True,
        limitations=limitations,
        stale_after="7 days from file analysis scan",
    )


def _build_blocked_candidate(
    entry: ActionCatalogEntry,
) -> ActionCandidate:
    """Build a candidate for a blocked action (informational only)."""
    return ActionCandidate(
        candidate_id=f"blocked.{entry.action_id}",
        action_id=entry.action_id,
        status=CandidateStatus.BLOCKED,
        title=entry.name,
        reason=(
            f"Blocked action exists but is not eligible. "
            f"Risk: {entry.risk_level.value}, "
            f"Blast radius: {entry.blast_radius.value}."
        ),
        eligibility_status=entry.eligibility.value,
        implementation_status=entry.implementation_status.value,
        risk_level=entry.risk_level.value,
        blast_radius=entry.blast_radius.value,
        reversible=entry.reversible,
        requires_admin=entry.requires_admin,
        limitations=["Action is explicitly blocked for safety reasons."],
    )


def _build_proposed_candidate(
    entry: ActionCatalogEntry,
) -> ActionCandidate:
    """Build a candidate for a proposed action (not executable)."""
    return ActionCandidate(
        candidate_id=f"proposed.{entry.action_id}",
        action_id=entry.action_id,
        status=CandidateStatus.PROPOSED,
        title=entry.name,
        reason=(
            f"Proposed action is not yet implemented. "
            f"Eligibility: {entry.eligibility.value}."
        ),
        eligibility_status=entry.eligibility.value,
        implementation_status=entry.implementation_status.value,
        risk_level=entry.risk_level.value,
        blast_radius=entry.blast_radius.value,
        reversible=entry.reversible,
        requires_admin=entry.requires_admin,
        limitations=["Action is proposed but not implemented."],
    )


def evaluate_candidates(ctx: PolicyContext) -> CandidatesSummary:
    """Evaluate all policy rules and return bounded candidate list.

    This is the main entry point for the policy engine.
    It is deterministic — same inputs produce same outputs.
    """
    candidates: list[ActionCandidate] = []

    # ── Evaluate production rules ──────────────────────────────────
    cleanup_entry = get_catalog_entry("disk.cleanup_temp")
    if cleanup_entry:
        c = _evaluate_cleanup_temp(ctx, cleanup_entry)
        if c:
            candidates.append(c)

    quarantine_entry = get_catalog_entry("user_temp_quarantine")
    if quarantine_entry:
        c = _evaluate_user_temp_quarantine(ctx, quarantine_entry)
        if c:
            candidates.append(c)

    # ── Add blocked actions (informational) ────────────────────────
    for entry in CATALOG.values():
        if entry.implementation_status == ImplementationStatus.BLOCKED:
            candidates.append(_build_blocked_candidate(entry))

    # ── Add proposed actions (informational) ───────────────────────
    for entry in CATALOG.values():
        if entry.implementation_status == ImplementationStatus.PROPOSED:
            candidates.append(_build_proposed_candidate(entry))

    # ── Bound the results ──────────────────────────────────────────
    bounded = candidates[:MAX_ACTION_CANDIDATES]

    # ── Build summary ──────────────────────────────────────────────
    available = sum(1 for c in bounded if c.status == CandidateStatus.AVAILABLE)
    proposed = sum(1 for c in bounded if c.status == CandidateStatus.PROPOSED)
    blocked = sum(1 for c in bounded if c.status == CandidateStatus.BLOCKED)
    insufficient = sum(1 for c in bounded if c.status == CandidateStatus.INSUFFICIENT_EVIDENCE)
    stale = sum(1 for c in bounded if c.status == CandidateStatus.STALE)

    return CandidatesSummary(
        available_count=available,
        proposed_count=proposed,
        blocked_count=blocked,
        insufficient_evidence_count=insufficient,
        stale_count=stale,
        total_count=len(bounded),
        candidates=bounded,
    )
