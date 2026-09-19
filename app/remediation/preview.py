"""Preview / Dry-Run mechanism for remediation actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.remediation.action import RemediationAction


@dataclass(frozen=True)
class PreviewResult:
    """Structured preview of what an action would do.

    The preview is a read-only description.  It must not cause any
    side effects on the machine.

    Attributes:
        action_id: The action being previewed.
        name: Human-readable action name.
        description: Detailed description of the action.
        risk_level: Risk classification.
        target: Resource that would be affected.
        reason: Why this action was proposed.
        requires_admin: Whether admin privileges are needed.
        reversible: Whether rollback is available.
        idempotent: Whether repeating is safe.
        would_change: Free-form description of what would change.
        what_is_not_guaranteed: Caveats and limitations.
        parameters: Action parameters (read-only copy).
        quarantine_plan: Quarantine-specific preview details, if applicable.
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


def preview_action(action: RemediationAction) -> PreviewResult:
    """Generate a preview for a proposed action.

    For the quarantine action, this performs a real scan without
    modifying anything.  For other actions, it returns a static preview.
    """
    what_is_not_guaranteed = [
        "This preview is based on the state at the time of analysis and may be stale.",
        "Actual execution may encounter errors not reflected in the preview.",
        "Rollback availability depends on the action implementation.",
        "No guarantee is made about side effects beyond the stated target.",
    ]

    quarantine_plan = None
    would_change = action.preview

    if action.action_id == "user_temp_quarantine":
        from app.remediation.quarantine import preview_quarantine, get_user_temp_dir

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
