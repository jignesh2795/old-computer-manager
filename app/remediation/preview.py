"""Read-only preview models and builder for action candidates.

Phase 11B: Candidate Preview Intelligence.

The preview layer generates a safe, deterministic, read-only description
of what WOULD happen if a remediation action were executed. It has NO
authority to execute, confirm, rollback, or modify the system.

Architecture:
    Evidence -> ActionCandidate -> PreviewBuilder -> Preview
                                                    -> Human-readable / JSON
                                                    -> Explicit confirmation
                                                    -> Existing validation/executor
                                                    -> Audit

Security constraints:
    - NO executor import
    - NO confirmation token import
    - NO rollback execution import
    - NO subprocess/shell/os.system
    - NO file writes or deletes
    - NO registry/service/task/startup modifications
    - Preview is informational only, never an authorization token
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class PreviewStatus(str, Enum):
    """Status of a generated preview."""

    READY = "ready"
    STALE = "stale"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True)
class PreviewItem:
    """A single affected target in a preview."""

    path: str
    size_bytes: int
    modified_at: str | None = None
    fingerprint: str = ""


@dataclass(frozen=True)
class Preview:
    """Read-only preview of what a remediation action would do.

    This is informational only. It is NOT an authorization token
    and does NOT grant permission to execute.
    """

    preview_id: str
    candidate_id: str
    action_id: str
    generated_at: str
    status: PreviewStatus
    title: str
    summary: str
    target: str
    affected_count: int
    affected_bytes: int
    affected_items: list[PreviewItem] = field(default_factory=list)
    expected_effect: str = ""
    side_effects: list[str] = field(default_factory=list)
    risk_level: str = ""
    blast_radius: str = ""
    reversible: bool = False
    rollback_available: bool = False
    rollback_description: str = ""
    requires_admin: bool = False
    confirmation_required: bool = True
    evidence: list[dict[str, Any]] = field(default_factory=list)
    source_runs: list[int] = field(default_factory=list)
    freshness_status: str = ""
    limitations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    omitted_count: int = 0
    fingerprint: str = ""
    permanent_deletion: bool = False


@dataclass(frozen=True)
class PreviewSummary:
    """Lightweight preview summary for reporting/AI context."""

    preview_id: str
    candidate_id: str
    action_id: str
    status: str
    affected_count: int
    affected_bytes: int
    risk_level: str
    reversible: bool
    rollback_available: bool
    expected_effect: str
    limitations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_PREVIEW_ITEMS = 20
MAX_PREVIEW_PATH_LENGTH = 500


# ---------------------------------------------------------------------------
# PreviewBuilder
# ---------------------------------------------------------------------------


class PreviewBuilder:
    """Deterministic, read-only preview builder.

    Uses ActionCandidate data, action catalog metadata, existing evidence,
    and stored analysis results to generate previews. Never uses an LLM.
    Never executes actions.
    """

    def build_preview(
        self,
        candidate: Any,
        policy_context: Any | None = None,
        file_analysis: dict[str, Any] | None = None,
    ) -> Preview:
        """Build a preview for the given candidate.

        Args:
            candidate: ActionCandidate to preview
            policy_context: Optional PolicyContext for evidence
            file_analysis: Optional file analysis data

        Returns:
            Preview with status-appropriate content
        """
        from app.remediation.candidates import CandidateStatus

        if candidate.status == CandidateStatus.AVAILABLE:
            return self._build_available_preview(candidate, policy_context, file_analysis)
        elif candidate.status == CandidateStatus.PROPOSED:
            return self._build_proposed_preview(candidate)
        elif candidate.status == CandidateStatus.BLOCKED:
            return self._build_blocked_preview(candidate)
        elif candidate.status == CandidateStatus.INSUFFICIENT_EVIDENCE:
            return self._build_insufficient_preview(candidate)
        elif candidate.status == CandidateStatus.STALE:
            return self._build_stale_preview(candidate)
        else:
            return self._build_unavailable_preview(candidate)

    # ------------------------------------------------------------------
    # Available candidate preview
    # ------------------------------------------------------------------

    def _build_available_preview(
        self,
        candidate: Any,
        policy_context: Any | None,
        file_analysis: dict[str, Any] | None,
    ) -> Preview:
        """Generate a complete preview for an available candidate."""
        from app.remediation.catalog import get_catalog_entry

        entry = get_catalog_entry(candidate.action_id)

        if candidate.action_id == "disk.cleanup_temp":
            return self._preview_cleanup_temp(candidate, entry, file_analysis)
        elif candidate.action_id == "user_temp_quarantine":
            return self._preview_quarantine(candidate, entry, file_analysis)
        else:
            return self._build_generic_available_preview(candidate, entry)

    def _preview_cleanup_temp(
        self,
        candidate: Any,
        entry: Any | None,
        file_analysis: dict[str, Any] | None,
    ) -> Preview:
        """Preview for disk.cleanup_temp action."""
        items: list[PreviewItem] = []
        total_bytes = 0
        eligible_files: list[dict[str, Any]] = []

        if file_analysis and "eligible_temp_files" in file_analysis:
            eligible_files = file_analysis["eligible_temp_files"]

        for f in eligible_files[:MAX_PREVIEW_ITEMS]:
            path = f.get("path", "")
            size = f.get("size_bytes", 0)
            items.append(PreviewItem(path=path, size_bytes=size))
            total_bytes += size

        omitted = max(0, len(eligible_files) - MAX_PREVIEW_ITEMS)

        affected_count = len(eligible_files)

        title = "Safe temp file cleanup (quarantine)"
        summary = (
            f"Would move {affected_count} eligible temp files "
            f"({self._bytes_human(total_bytes)}) to the quarantine directory."
        )

        evidence_dicts = []
        for ev in candidate.evidence:
            evidence_dicts.append({
                "source_type": ev.source_type.value if hasattr(ev.source_type, "value") else str(ev.source_type),
                "source_id": ev.source_id,
                "observation": ev.observation,
            })

        fingerprint = self._compute_fingerprint(items)

        return Preview(
            preview_id=f"preview:{candidate.candidate_id}",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            status=PreviewStatus.READY,
            title=title,
            summary=summary,
            target="User TEMP directory",
            affected_count=affected_count,
            affected_bytes=total_bytes,
            affected_items=items,
            expected_effect="Move eligible files to the application quarantine directory",
            side_effects=["Files will be inaccessible from original location until restored"],
            risk_level="medium",
            blast_radius="user_directory",
            reversible=True,
            rollback_available=True,
            rollback_description="Restore quarantined files to their original paths. Refuses to overwrite existing files.",
            requires_admin=False,
            confirmation_required=True,
            evidence=evidence_dicts,
            source_runs=[candidate.discovery_run_id] if candidate.discovery_run_id else [],
            freshness_status="within_window",
            limitations=["Preview reflects file analysis at time of discovery"],
            warnings=["Files created after discovery may not be included"],
            omitted_count=omitted,
            fingerprint=fingerprint,
            permanent_deletion=False,
        )

    def _preview_quarantine(
        self,
        candidate: Any,
        entry: Any | None,
        file_analysis: dict[str, Any] | None,
    ) -> Preview:
        """Preview for user_temp_quarantine action."""
        return Preview(
            preview_id=f"preview:{candidate.candidate_id}",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            status=PreviewStatus.READY,
            title="User temp file quarantine",
            summary="Would move eligible temp files to the quarantine directory.",
            target="User TEMP directory",
            affected_count=0,
            affected_bytes=0,
            expected_effect="Move eligible temp files to quarantine",
            risk_level="medium",
            blast_radius="user_directory",
            reversible=True,
            rollback_available=True,
            rollback_description="Restore quarantined files to their original paths.",
            requires_admin=False,
            confirmation_required=True,
            freshness_status="within_window",
        )

    def _build_generic_available_preview(self, candidate: Any, entry: Any | None) -> Preview:
        """Generic preview for other available candidates."""
        risk = candidate.risk_level if hasattr(candidate, "risk_level") else ""
        return Preview(
            preview_id=f"preview:{candidate.candidate_id}",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            status=PreviewStatus.READY,
            title=candidate.title,
            summary=candidate.reason,
            target="System",
            affected_count=0,
            affected_bytes=0,
            expected_effect=candidate.title,
            risk_level=risk,
            reversible=candidate.reversible if hasattr(candidate, "reversible") else False,
            requires_admin=candidate.requires_admin if hasattr(candidate, "requires_admin") else False,
            confirmation_required=True,
            limitations=["Preview not fully implemented for this action"],
        )

    # ------------------------------------------------------------------
    # Proposed candidate preview
    # ------------------------------------------------------------------

    def _build_proposed_preview(self, candidate: Any) -> Preview:
        """Design-only preview for proposed (not implemented) actions."""
        return Preview(
            preview_id=f"preview:{candidate.candidate_id}",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            status=PreviewStatus.UNAVAILABLE,
            title=candidate.title,
            summary=candidate.reason,
            target="Not implemented",
            affected_count=0,
            affected_bytes=0,
            expected_effect="No execution possible: action is proposed but not implemented",
            risk_level=candidate.risk_level if hasattr(candidate, "risk_level") else "",
            reversible=False,
            rollback_available=False,
            requires_admin=False,
            confirmation_required=False,
            limitations=["Action is proposed but not implemented", "No execution preview available"],
            warnings=["This action cannot be executed in the current version"],
        )

    # ------------------------------------------------------------------
    # Blocked candidate preview
    # ------------------------------------------------------------------

    def _build_blocked_preview(self, candidate: Any) -> Preview:
        """Preview explaining why a blocked action cannot execute."""
        return Preview(
            preview_id=f"preview:{candidate.candidate_id}",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            status=PreviewStatus.BLOCKED,
            title=candidate.title,
            summary=candidate.reason,
            target="Blocked",
            affected_count=0,
            affected_bytes=0,
            expected_effect="No execution possible: action is explicitly blocked for safety",
            risk_level=candidate.risk_level if hasattr(candidate, "risk_level") else "",
            reversible=candidate.reversible if hasattr(candidate, "reversible") else False,
            rollback_available=False,
            requires_admin=False,
            confirmation_required=False,
            limitations=["Action is explicitly blocked", "No execution preview available"],
            warnings=["This action is blocked due to high risk or system-wide blast radius"],
        )

    # ------------------------------------------------------------------
    # Insufficient evidence preview
    # ------------------------------------------------------------------

    def _build_insufficient_preview(self, candidate: Any) -> Preview:
        """Preview explaining missing evidence."""
        return Preview(
            preview_id=f"preview:{candidate.candidate_id}",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            status=PreviewStatus.INSUFFICIENT_EVIDENCE,
            title=candidate.title,
            summary=candidate.reason,
            target="Unknown",
            affected_count=0,
            affected_bytes=0,
            expected_effect="Cannot determine: insufficient evidence to identify affected items",
            risk_level=candidate.risk_level if hasattr(candidate, "risk_level") else "",
            reversible=candidate.reversible if hasattr(candidate, "reversible") else False,
            rollback_available=False,
            requires_admin=False,
            confirmation_required=False,
            limitations=candidate.limitations if hasattr(candidate, "limitations") else [],
            warnings=["Missing evidence prevents preview generation"],
        )

    # ------------------------------------------------------------------
    # Stale evidence preview
    # ------------------------------------------------------------------

    def _build_stale_preview(self, candidate: Any) -> Preview:
        """Preview explaining stale evidence."""
        stale_info = ""
        if hasattr(candidate, "stale_after") and candidate.stale_after:
            stale_info = f"Evidence freshness window: {candidate.stale_after}"

        return Preview(
            preview_id=f"preview:{candidate.candidate_id}",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            status=PreviewStatus.STALE,
            title=candidate.title,
            summary="Evidence is stale and cannot be used to generate a current preview",
            target="Unknown (stale)",
            affected_count=0,
            affected_bytes=0,
            expected_effect="Cannot determine: evidence has expired",
            risk_level=candidate.risk_level if hasattr(candidate, "risk_level") else "",
            reversible=candidate.reversible if hasattr(candidate, "reversible") else False,
            rollback_available=False,
            requires_admin=False,
            confirmation_required=False,
            limitations=[stale_info, "Stale evidence cannot identify current targets"],
            warnings=["Evidence is expired. A fresh discovery is required before previewing."],
        )

    # ------------------------------------------------------------------
    # Unavailable preview
    # ------------------------------------------------------------------

    def _build_unavailable_preview(self, candidate: Any) -> Preview:
        """Preview for unknown/unavailable status."""
        return Preview(
            preview_id=f"preview:{candidate.candidate_id}",
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            status=PreviewStatus.UNAVAILABLE,
            title=candidate.title,
            summary="Preview unavailable",
            target="Unknown",
            affected_count=0,
            affected_bytes=0,
            risk_level="",
            limitations=["Preview status is unknown"],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _bytes_human(n: int) -> str:
        """Format bytes as human-readable string."""
        if n < 1024:
            return f"{n} B"
        elif n < 1024 * 1024:
            return f"{n / 1024:.1f} KB"
        elif n < 1024 * 1024 * 1024:
            return f"{n / (1024 * 1024):.1f} MB"
        else:
            return f"{n / (1024 * 1024 * 1024):.2f} GB"

    @staticmethod
    def _compute_fingerprint(items: list[PreviewItem]) -> str:
        """Compute deterministic fingerprint from affected items."""
        if not items:
            return ""
        parts = []
        for item in items:
            parts.append(f"{item.path}:{item.size_bytes}:{item.modified_at or ''}")
        combined = "|".join(parts)
        return hashlib.sha256(combined.encode()).hexdigest()[:16]


def build_preview(
    candidate: Any,
    policy_context: Any | None = None,
    file_analysis: dict[str, Any] | None = None,
) -> Preview:
    """Convenience function to build a preview for a candidate.

    This is the main entry point for preview generation.
    """
    builder = PreviewBuilder()
    return builder.build_preview(candidate, policy_context, file_analysis)


# ===========================================================================
# Phase 10A: Legacy preview for remediation actions (PreviewResult)
# ===========================================================================


@dataclass(frozen=True)
class PreviewResult:
    """Structured preview of what an action would do.

    The preview is a read-only description.  It must not cause any
    side effects on the machine.
    """

    action_id: str
    name: str
    description: str
    risk_level: str
    target: str
    reason: str
    requires_admin: bool
    reversible: bool
    idempotent: bool
    would_change: str
    what_is_not_guaranteed: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    quarantine_plan: Any = None


def preview_action(action: Any) -> PreviewResult:
    """Generate a preview for a proposed action.

    For the quarantine action, this performs a real scan without
    modifying anything.  For other actions, it returns a static preview.
    """
    from app.remediation.action import RemediationAction

    what_is_not_guaranteed = [
        "This preview is based on the state at the time of analysis and may be stale.",
        "Actual execution may encounter errors not reflected in the preview.",
        "Rollback availability depends on the action implementation.",
        "No guarantee is made about side effects beyond the stated target.",
    ]

    quarantine_plan = None
    would_change = action.preview

    if action.action_id == "user_temp_quarantine":
        from app.remediation.quarantine import preview_quarantine

        age_days = action.parameters.get("age_days", 7)
        plan = preview_quarantine(age_threshold_days=age_days)
        quarantine_plan = plan

        would_change = (
            f"Would move {plan.files_eligible} files "
            f"({plan.total_size_bytes:,} bytes) from {plan.source_dir} "
            f"to {plan.quarantine_dir}.  Files are moved, not deleted."
        )

        if plan.files_eligible == 0:
            would_change = (
                f"Scan of {plan.source_dir} found {plan.files_examined} files "
                f"but none are eligible for quarantine (age threshold: "
                f"{plan.age_threshold_days} days)."
            )

        what_is_not_guaranteed = [
            "Preview is based on current filesystem state and may change before execution.",
            "Files created or modified between preview and execution may change eligibility.",
            "Access-denied files will be skipped during execution.",
            "Quarantine directory will be created if it does not exist.",
            "Rollback restores files to their original location.",
        ]

    elif action.action_id == "disk.cleanup_temp":
        from app.remediation.cleanup_temp import preview_cleanup

        age_days = action.parameters.get("age_days", 30)
        preview = preview_cleanup(age_days=age_days)
        quarantine_plan = preview

        would_change = (
            f"Would move {preview.candidates} files "
            f"({preview.total_size_bytes:,} bytes) from {preview.source_dir} "
            f"to {preview.quarantine_dir}.  Files are moved, not deleted.  "
            f"Max files per execution: {preview.max_files_per_execution}."
        )

        if preview.candidates == 0:
            would_change = (
                f"Scan of {preview.source_dir} found {preview.files_examined} files "
                f"but none are eligible for quarantine (age threshold: "
                f"{preview.age_threshold_days} days)."
            )
        elif preview.limit_exceeded:
            would_change += (
                f"  WARNING: {preview.candidates} candidates exceeds "
                f"limit; only {preview.max_files_per_execution} will be moved."
            )

        what_is_not_guaranteed = [
            "Preview is based on current filesystem state and may change before execution.",
            "Files created or modified between preview and execution may change eligibility.",
            "Access-denied files will be skipped during execution.",
            "Quarantine directory will be created if it does not exist.",
            "Rollback restores files to their original location.",
            "MAX_FILES_PER_EXECUTION=500 enforced; excess candidates are skipped.",
        ]

    return PreviewResult(
        action_id=action.action_id,
        name=action.name,
        description=action.description,
        risk_level=action.risk_level.value,
        target=action.target,
        reason=action.reason,
        requires_admin=action.requires_admin,
        reversible=action.reversible,
        idempotent=action.idempotent,
        would_change=would_change,
        what_is_not_guaranteed=what_is_not_guaranteed,
        parameters=dict(action.parameters),
        quarantine_plan=quarantine_plan,
    )
