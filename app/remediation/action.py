"""RemediationAction model -- the core typed dataclass for proposed actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    """Risk classification for a remediation action.

    Do not automatically assume low risk is safe.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ImplementationStatus(str, Enum):
    """Whether an action is implemented, proposed, or blocked.

    Only IMPLEMENTED actions may be executed through the controlled
    remediation workflow.  All other statuses are informational.
    """

    IMPLEMENTED = "implemented"
    PROPOSED = "proposed"
    BLOCKED = "blocked"
    NOT_IMPLEMENTED = "not_implemented"


class BlastRadius(str, Enum):
    """Scope of system impact if action misbehaves.

    Used to communicate blast radius during risk review.
    """

    SINGLE_FILE = "single_file"
    USER_DIRECTORY = "user_directory"
    USER_PROFILE = "user_profile"
    SYSTEM_WIDE = "system_wide"
    BOOTLOADER = "bootloader"


class RollbackCategory(str, Enum):
    """How rollback is achieved for an action.

    NOT_APPLICABLE means no rollback mechanism is implemented.
    """

    SHUTIL_MOVE_RESTORE = "shutil_move_restore"
    REGISTRY_RESTORE = "registry_restore"
    SERVICE_RESTORE = "service_restore"
    STARTUP_RESTORE = "startup_restore"
    SNAPSHOT_RESTORE = "snapshot_restore"
    NOT_APPLICABLE = "not_applicable"


class EligibilityStatus(str, Enum):
    """Whether an action is eligible for execution.

    Only ELIGIBLE actions may proceed through the confirmation and
    execution pipeline.
    """

    ELIGIBLE = "eligible"
    BLOCKED = "blocked"
    REQUIRES_DESIGN_REVIEW = "requires_design_review"
    REQUIRES_PRIVILEGE_REVIEW = "requires_privilege_review"
    REQUIRES_ROLLBACK_DESIGN = "requires_rollback_design"


@dataclass(frozen=True)
class RemediationAction:
    """A proposed remediation action.  Immutable.

    This model represents an *intent* to perform a remediation, not
    permission to execute it.  Constructing an instance does NOT grant
    authority to modify the system.

    Attributes:
        action_id: Stable identifier for the action type (registry key).
        name: Short human-readable name.
        description: Detailed explanation of what the action does.
        risk_level: Risk classification.
        target: Description of the resource that would be affected.
        reason: Why this action is being proposed.
        finding_id: Database ID of the originating finding, if any.
        discovery_run_id: Database ID of the discovery run, if any.
        requires_admin: Whether administrator privileges are required.
        reversible: Whether the action can be undone via rollback.
        preview: Summary of what would change (read-only description).
        parameters: Arbitrary key-value pairs for the action implementation.
        idempotent: Whether repeating this action is safe when the state
                    already matches the desired outcome.
        implementation_status: Lifecycle status of this action definition.
        blast_radius: Scope of system impact if action misbehaves.
        rollback_category: How rollback is achieved.
        dependencies: Action IDs this action depends on.
        eligibility: Whether this action is eligible for execution.
        action_version: Version of the action definition schema.
        category: Functional category (e.g. "cleanup", "security", "demo/test").
    """

    action_id: str
    name: str
    description: str
    risk_level: RiskLevel
    target: str
    reason: str
    finding_id: int | None = None
    discovery_run_id: int | None = None
    requires_admin: bool = False
    reversible: bool = False
    preview: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    idempotent: bool = False
    implementation_status: ImplementationStatus = ImplementationStatus.NOT_IMPLEMENTED
    blast_radius: BlastRadius = BlastRadius.SINGLE_FILE
    rollback_category: RollbackCategory = RollbackCategory.NOT_APPLICABLE
    dependencies: tuple[str, ...] = ()
    eligibility: EligibilityStatus = EligibilityStatus.REQUIRES_DESIGN_REVIEW
    action_version: str = "1"
    category: str = "general"

    def __post_init__(self) -> None:
        # Validate risk_level is a valid RiskLevel member.
        # With str Enum, invalid strings don't raise -- they auto-create members.
        valid_values = {e.value for e in RiskLevel}
        raw = self.risk_level.value if isinstance(self.risk_level, RiskLevel) else str(self.risk_level)
        if raw not in valid_values:
            raise ValueError(
                f"Invalid risk_level '{raw}'. "
                f"Must be one of: {', '.join(sorted(valid_values))}"
            )
