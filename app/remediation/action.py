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
