"""Read-only candidate preview models and builder (Phase 11B).

Generates safe, deterministic previews for ActionCandidates.
Explains what WOULD happen if an action were executed, without
performing any modification.

Architecture:
    Evidence -> ActionCandidate -> CandidatePreviewBuilder -> Preview
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

Note: Legacy action preview (PreviewResult, preview_action) has been
moved to action_preview.py for maintainability.
"""

from __future__ import annotations

import hashlib
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
    implementation_status: str = ""
    implementation_status_text: str = ""


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
# CandidatePreviewBuilder
# ---------------------------------------------------------------------------


class CandidatePreviewBuilder:
    """Deterministic, read-only preview builder for ActionCandidates.

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
        if candidate.action_id == "disk.cleanup_temp":
            return self._preview_cleanup_temp(candidate, file_analysis)
        elif candidate.action_id == "user_temp_quarantine":
            return self._preview_quarantine(candidate)
        else:
            return self._build_generic_available_preview(candidate)

    def _preview_cleanup_temp(
        self,
        candidate: Any,
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
            implementation_status="implemented",
            implementation_status_text="Action is implemented and eligible for execution after confirmation.",
        )

    def _preview_quarantine(self, candidate: Any) -> Preview:
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

    def _build_generic_available_preview(self, candidate: Any) -> Preview:
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
            implementation_status="proposed",
            implementation_status_text="Action is designed but not yet implemented. No execution path exists.",
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
            implementation_status="blocked",
            implementation_status_text="Action is explicitly blocked. Risk or blast radius prevents execution.",
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
            implementation_status="insufficient_evidence",
            implementation_status_text="Action may be eligible but evidence is insufficient to identify targets.",
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
            implementation_status="stale",
            implementation_status_text="Evidence has expired. A fresh discovery is required.",
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


# ---------------------------------------------------------------------------
# Module-level convenience alias
# ---------------------------------------------------------------------------

PreviewBuilder = CandidatePreviewBuilder


def build_preview(
    candidate: Any,
    policy_context: Any | None = None,
    file_analysis: dict[str, Any] | None = None,
) -> Preview:
    """Convenience function to build a preview for a candidate.

    This is the main entry point for preview generation.
    """
    builder = CandidatePreviewBuilder()
    return builder.build_preview(candidate, policy_context, file_analysis)
