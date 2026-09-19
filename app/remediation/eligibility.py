"""Action Eligibility Gate -- determines whether an action is eligible for execution.

Only ELIGIBLE actions may proceed through the confirmation and execution
pipeline.  This gate is the single decision point for "can this action
be executed at all?".

SAFETY: This module is a READ-ONLY decision gate.  It does NOT grant
execution authority, modify the system, or bypass the confirmation flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.remediation.action import EligibilityStatus, ImplementationStatus
from app.remediation.catalog import (
    CATALOG,
    ActionCatalogEntry,
    get_catalog_entry,
)


@dataclass(frozen=True)
class EligibilityResult:
    """Result of an eligibility check.

    Attributes:
        action_id: The action that was checked.
        status: The eligibility decision.
        reason: Human-readable explanation.
        blockers: Specific reasons the action is blocked.
        warnings: Non-blocking concerns.
    """

    action_id: str
    status: EligibilityStatus
    reason: str = ""
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def check_eligibility(action_id: str) -> EligibilityResult:
    """Check whether an action is eligible for execution.

    This is the single decision point.  Returns an EligibilityResult
    with status ELIGIBLE, BLOCKED, REQUIRES_DESIGN_REVIEW,
    REQUIRES_PRIVILEGE_REVIEW, or REQUIRES_ROLLBACK_DESIGN.
    """
    entry = get_catalog_entry(action_id)

    if entry is None:
        return EligibilityResult(
            action_id=action_id,
            status=EligibilityStatus.REQUIRES_DESIGN_REVIEW,
            reason=f"Action '{action_id}' is not in the catalog.",
        )

    # BLOCKED actions are never eligible
    if entry.implementation_status == ImplementationStatus.BLOCKED:
        return EligibilityResult(
            action_id=action_id,
            status=EligibilityStatus.BLOCKED,
            reason=(
                f"Action '{action_id}' is explicitly blocked.  "
                "System-modifying actions in this category are not permitted."
            ),
            blockers=[
                f"Risk level: {entry.risk_level.value}",
                f"Blast radius: {entry.blast_radius.value}",
                "Action is in the BLOCKED category for safety reasons.",
            ],
        )

    # NOT_IMPLEMENTED actions require design review
    if entry.implementation_status == ImplementationStatus.NOT_IMPLEMENTED:
        return EligibilityResult(
            action_id=action_id,
            status=EligibilityStatus.REQUIRES_DESIGN_REVIEW,
            reason=f"Action '{action_id}' is not yet implemented.",
        )

    # PROPOSED actions need review based on eligibility
    if entry.implementation_status == ImplementationStatus.PROPOSED:
        if entry.eligibility == EligibilityStatus.REQUIRES_ROLLBACK_DESIGN:
            return EligibilityResult(
                action_id=action_id,
                status=EligibilityStatus.REQUIRES_ROLLBACK_DESIGN,
                reason=(
                    f"Action '{action_id}' is proposed but requires "
                    "rollback design before implementation."
                ),
                warnings=[
                    "No rollback mechanism is currently defined.",
                    "Action would be irreversible if implemented as-is.",
                ],
            )
        if entry.eligibility == EligibilityStatus.REQUIRES_DESIGN_REVIEW:
            return EligibilityResult(
                action_id=action_id,
                status=EligibilityStatus.REQUIRES_DESIGN_REVIEW,
                reason=(
                    f"Action '{action_id}' is proposed but requires "
                    "design review before implementation."
                ),
            )
        return EligibilityResult(
            action_id=action_id,
            status=entry.eligibility,
            reason=f"Action '{action_id}' is proposed.",
        )

    # IMPLEMENTED actions: check admin privileges if required
    if entry.implementation_status == ImplementationStatus.IMPLEMENTED:
        if entry.requires_admin:
            from app.remediation.permissions import check_admin_privileges

            priv = check_admin_privileges()
            if not priv.is_admin:
                return EligibilityResult(
                    action_id=action_id,
                    status=EligibilityStatus.REQUIRES_PRIVILEGE_REVIEW,
                    reason=(
                        f"Action '{action_id}' requires administrator "
                        "privileges but the current process is not elevated."
                    ),
                    warnings=[
                        "Re-run as administrator to enable this action.",
                    ],
                )
        return EligibilityResult(
            action_id=action_id,
            status=EligibilityStatus.ELIGIBLE,
            reason=f"Action '{action_id}' is implemented and eligible.",
        )

    # Fallback
    return EligibilityResult(
        action_id=action_id,
        status=EligibilityStatus.REQUIRES_DESIGN_REVIEW,
        reason=f"Action '{action_id}' has unknown status.",
    )


def is_action_allowed(action_id: str) -> bool:
    """Quick check: is this action eligible for execution?

    Returns True only for ELIGIBLE actions.
    """
    result = check_eligibility(action_id)
    return result.status == EligibilityStatus.ELIGIBLE


def get_blocked_actions() -> list[ActionCatalogEntry]:
    """Return all BLOCKED catalog entries."""
    return [
        e for e in CATALOG.values()
        if e.implementation_status == ImplementationStatus.BLOCKED
    ]


def get_proposed_actions() -> list[ActionCatalogEntry]:
    """Return all PROPOSED catalog entries."""
    return [
        e for e in CATALOG.values()
        if e.implementation_status == ImplementationStatus.PROPOSED
    ]


def get_implemented_actions() -> list[ActionCatalogEntry]:
    """Return all IMPLEMENTED catalog entries (production + demo)."""
    return [
        e for e in CATALOG.values()
        if e.implementation_status == ImplementationStatus.IMPLEMENTED
    ]


def get_implemented_production_actions() -> list[ActionCatalogEntry]:
    """Return IMPLEMENTED actions that are NOT demo/test.

    Used for user-facing production remediation display.
    """
    return [
        e for e in CATALOG.values()
        if e.implementation_status == ImplementationStatus.IMPLEMENTED
        and e.category != "demo/test"
    ]
