"""Action Catalog -- structured metadata for all remediation actions.

Defines the complete catalog of known actions with their risk model,
eligibility rules, blast radius, rollback categories, dependencies,
and implementation status.  This is the single source of truth for
Phase 9A framework decisions.

SAFETY: This module is READ-ONLY metadata.  It does NOT register actions
in the registry, grant execution authority, or modify the system.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.remediation.action import (
    BlastRadius,
    EligibilityStatus,
    ImplementationStatus,
    RiskLevel,
    RollbackCategory,
)


@dataclass(frozen=True)
class ActionCatalogEntry:
    """Structured metadata for a single remediation action.

    This is a catalog/risk-review entry, not an execution permission.
    """

    action_id: str
    name: str
    description: str
    risk_level: RiskLevel
    implementation_status: ImplementationStatus
    blast_radius: BlastRadius
    rollback_category: RollbackCategory
    eligibility: EligibilityStatus
    requires_admin: bool
    reversible: bool
    dependencies: tuple[str, ...] = ()
    action_version: str = "1"
    category: str = "general"


def _build_catalog() -> dict[str, ActionCatalogEntry]:
    """Build the master catalog.  Called once at import time."""
    entries: list[ActionCatalogEntry] = [
        # ── Implemented production actions ──────────────────────────
        ActionCatalogEntry(
            action_id="user_temp_quarantine",
            name="Quarantine old temporary files",
            description=(
                "Moves temporary files older than the configured age "
                "threshold from the user TEMP directory into quarantine.  "
                "Files are NEVER permanently deleted."
            ),
            risk_level=RiskLevel.MEDIUM,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            blast_radius=BlastRadius.USER_DIRECTORY,
            rollback_category=RollbackCategory.SHUTIL_MOVE_RESTORE,
            eligibility=EligibilityStatus.ELIGIBLE,
            requires_admin=False,
            reversible=True,
            category="cleanup",
        ),
        # ── Demo / test actions (NOT production) ───────────────────
        ActionCatalogEntry(
            action_id="demo.noop.print_message",
            name="Print a message (no-op)",
            description=(
                "A demonstration action that simulates printing a message.  "
                "Performs no real I/O and modifies nothing."
            ),
            risk_level=RiskLevel.LOW,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            blast_radius=BlastRadius.SINGLE_FILE,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.ELIGIBLE,
            requires_admin=False,
            reversible=True,
            category="demo/test",
        ),
        ActionCatalogEntry(
            action_id="demo.noop.report_status",
            name="Report system status (no-op)",
            description=(
                "A demonstration action that simulates reporting system "
                "status.  Performs no real checks and modifies nothing."
            ),
            risk_level=RiskLevel.LOW,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            blast_radius=BlastRadius.SINGLE_FILE,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.ELIGIBLE,
            requires_admin=False,
            reversible=True,
            category="demo/test",
        ),
        # ── Blocked actions (explicitly unsafe) ────────────────────
        ActionCatalogEntry(
            action_id="startup.disable_entry",
            name="Disable startup entry",
            description="Disables a Windows startup entry to prevent auto-launch.",
            risk_level=RiskLevel.HIGH,
            implementation_status=ImplementationStatus.BLOCKED,
            blast_radius=BlastRadius.SYSTEM_WIDE,
            rollback_category=RollbackCategory.STARTUP_RESTORE,
            eligibility=EligibilityStatus.BLOCKED,
            requires_admin=True,
            reversible=True,
            category="startup",
        ),
        ActionCatalogEntry(
            action_id="service.stop_temporary",
            name="Stop temporary service",
            description="Stops a running Windows service until next reboot.",
            risk_level=RiskLevel.CRITICAL,
            implementation_status=ImplementationStatus.BLOCKED,
            blast_radius=BlastRadius.SYSTEM_WIDE,
            rollback_category=RollbackCategory.SERVICE_RESTORE,
            eligibility=EligibilityStatus.BLOCKED,
            requires_admin=True,
            reversible=True,
            category="services",
        ),
        ActionCatalogEntry(
            action_id="service.disable_unused",
            name="Disable unused service",
            description="Disables a Windows service so it does not start on boot.",
            risk_level=RiskLevel.CRITICAL,
            implementation_status=ImplementationStatus.BLOCKED,
            blast_radius=BlastRadius.SYSTEM_WIDE,
            rollback_category=RollbackCategory.SERVICE_RESTORE,
            eligibility=EligibilityStatus.BLOCKED,
            requires_admin=True,
            reversible=True,
            category="services",
        ),
        ActionCatalogEntry(
            action_id="software.uninstall",
            name="Uninstall software",
            description="Uninstalls a software package from the system.",
            risk_level=RiskLevel.CRITICAL,
            implementation_status=ImplementationStatus.BLOCKED,
            blast_radius=BlastRadius.SYSTEM_WIDE,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.BLOCKED,
            requires_admin=True,
            reversible=False,
            category="software",
        ),
        ActionCatalogEntry(
            action_id="network.proxy_configure",
            name="Configure network proxy",
            description="Modifies system proxy settings.",
            risk_level=RiskLevel.CRITICAL,
            implementation_status=ImplementationStatus.BLOCKED,
            blast_radius=BlastRadius.SYSTEM_WIDE,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.BLOCKED,
            requires_admin=True,
            reversible=True,
            category="network",
        ),
        ActionCatalogEntry(
            action_id="power.plan_optimize",
            name="Optimize power plan",
            description="Modifies Windows power plan settings.",
            risk_level=RiskLevel.HIGH,
            implementation_status=ImplementationStatus.BLOCKED,
            blast_radius=BlastRadius.SYSTEM_WIDE,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.BLOCKED,
            requires_admin=True,
            reversible=True,
            category="power",
        ),
        # ── Proposed actions (designed but not implemented) ─────────
        ActionCatalogEntry(
            action_id="disk.cleanup_temp",
            name="Cleanup old temp files (delete)",
            description="Deletes temporary files older than age threshold.",
            risk_level=RiskLevel.MEDIUM,
            implementation_status=ImplementationStatus.PROPOSED,
            blast_radius=BlastRadius.USER_DIRECTORY,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.REQUIRES_ROLLBACK_DESIGN,
            requires_admin=False,
            reversible=False,
            category="cleanup",
        ),
        ActionCatalogEntry(
            action_id="disk.cleanup_logs",
            name="Cleanup old log files",
            description="Deletes log files older than age threshold.",
            risk_level=RiskLevel.MEDIUM,
            implementation_status=ImplementationStatus.PROPOSED,
            blast_radius=BlastRadius.USER_DIRECTORY,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.REQUIRES_ROLLBACK_DESIGN,
            requires_admin=False,
            reversible=False,
            category="cleanup",
        ),
        ActionCatalogEntry(
            action_id="browser.cache_clear",
            name="Clear browser cache",
            description="Clears cached browser data.",
            risk_level=RiskLevel.LOW,
            implementation_status=ImplementationStatus.PROPOSED,
            blast_radius=BlastRadius.USER_DIRECTORY,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.REQUIRES_DESIGN_REVIEW,
            requires_admin=False,
            reversible=False,
            category="cleanup",
        ),
        ActionCatalogEntry(
            action_id="update.check_only",
            name="Check for Windows updates",
            description="Checks for available Windows updates (read-only).",
            risk_level=RiskLevel.LOW,
            implementation_status=ImplementationStatus.PROPOSED,
            blast_radius=BlastRadius.SINGLE_FILE,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.REQUIRES_DESIGN_REVIEW,
            requires_admin=False,
            reversible=True,
            category="diagnostic",
        ),
    ]
    return {e.action_id: e for e in entries}


CATALOG: dict[str, ActionCatalogEntry] = _build_catalog()


def get_catalog_entry(action_id: str) -> ActionCatalogEntry | None:
    """Look up a catalog entry by action_id.  Returns None if unknown."""
    return CATALOG.get(action_id)


def get_catalog_entries_by_status(
    status: ImplementationStatus,
) -> list[ActionCatalogEntry]:
    """Return all catalog entries with the given implementation status."""
    return [e for e in CATALOG.values() if e.implementation_status == status]


def get_catalog_entries_by_eligibility(
    eligibility: EligibilityStatus,
) -> list[ActionCatalogEntry]:
    """Return all catalog entries with the given eligibility status."""
    return [e for e in CATALOG.values() if e.eligibility == eligibility]


def get_production_entries() -> list[ActionCatalogEntry]:
    """Return catalog entries that are NOT demo/test category.

    Used by the frontend to display only production actions.
    """
    return [e for e in CATALOG.values() if e.category != "demo/test"]


def validate_catalog_consistency() -> list[str]:
    """Validate that the catalog is internally consistent.

    Returns a list of error strings.  Empty list means no issues.
    """
    errors: list[str] = []
    seen_ids: set[str] = set()

    for entry in CATALOG.values():
        # Duplicate check
        if entry.action_id in seen_ids:
            errors.append(f"Duplicate action_id in catalog: {entry.action_id}")
        seen_ids.add(entry.action_id)

        # BLOCKED actions must not be ELIGIBLE
        if (
            entry.implementation_status == ImplementationStatus.BLOCKED
            and entry.eligibility == EligibilityStatus.ELIGIBLE
        ):
            errors.append(
                f"Action '{entry.action_id}' is BLOCKED but marked ELIGIBLE."
            )

        # NOT_IMPLEMENTED actions must not be ELIGIBLE
        if (
            entry.implementation_status == ImplementationStatus.NOT_IMPLEMENTED
            and entry.eligibility == EligibilityStatus.ELIGIBLE
        ):
            errors.append(
                f"Action '{entry.action_id}' is NOT_IMPLEMENTED but marked ELIGIBLE."
            )

        # IMPLEMENTED actions must be ELIGIBLE
        if (
            entry.implementation_status == ImplementationStatus.IMPLEMENTED
            and entry.eligibility != EligibilityStatus.ELIGIBLE
        ):
            errors.append(
                f"Action '{entry.action_id}' is IMPLEMENTED but not ELIGIBLE."
            )

        # Demo/test actions must have category="demo/test"
        if entry.action_id.startswith("demo.") and entry.category != "demo/test":
            errors.append(
                f"Action '{entry.action_id}' starts with 'demo.' but "
                f"category is '{entry.category}', expected 'demo/test'."
            )

        # Dependencies must reference known actions
        for dep_id in entry.dependencies:
            if dep_id not in CATALOG:
                errors.append(
                    f"Action '{entry.action_id}' depends on unknown "
                    f"action '{dep_id}'."
                )

    return errors
