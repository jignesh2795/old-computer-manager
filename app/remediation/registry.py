"""Action Registry -- every remediation action must be registered here."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.remediation.action import (
    BlastRadius,
    EligibilityStatus,
    ImplementationStatus,
    RemediationAction,
    RiskLevel,
    RollbackCategory,
)


class DuplicateActionError(Exception):
    """Raised when registering an action with an existing action_id."""


class UnknownActionError(Exception):
    """Raised when looking up an unregistered action_id."""


@dataclass(frozen=True)
class ParameterSchema:
    """Schema declaring expected parameters for an action.

    Attributes:
        required: Set of parameter names that must be present.
        optional: Set of parameter names that may be present.
        types: Mapping of parameter name -> expected Python type name.
        values: Mapping of parameter name -> set of allowed values (None = any).
    """

    required: set[str] = field(default_factory=set)
    optional: set[str] = field(default_factory=set)
    types: dict[str, str] = field(default_factory=dict)
    values: dict[str, set[Any]] = field(default_factory=dict)


class ActionRegistry:
    """Central registry of all permitted remediation actions.

    Actions must be explicitly registered before they can be proposed,
    previewed, confirmed, or executed.  Duplicate action_ids are rejected.

    The registry is intentionally separate from the action model so that
    constructing a RemediationAction instance alone is never sufficient
    to gain execution authority.
    """

    def __init__(self) -> None:
        self._actions: dict[str, RemediationAction] = {}
        self._schemas: dict[str, ParameterSchema] = {}

    def register(
        self,
        action: RemediationAction,
        *,
        parameter_schema: ParameterSchema | None = None,
    ) -> None:
        """Register an action.  Raises DuplicateActionError on conflict."""
        if action.action_id in self._actions:
            raise DuplicateActionError(
                f"Action '{action.action_id}' is already registered."
            )
        self._actions[action.action_id] = action
        if parameter_schema is not None:
            self._schemas[action.action_id] = parameter_schema

    def get(self, action_id: str) -> RemediationAction:
        """Look up an action by id.  Raises UnknownActionError if missing."""
        try:
            return self._actions[action_id]
        except KeyError:
            raise UnknownActionError(
                f"Action '{action_id}' is not registered."
            )

    def get_schema(self, action_id: str) -> ParameterSchema | None:
        """Look up the parameter schema for an action, or None."""
        return self._schemas.get(action_id)

    def list_actions(self) -> list[RemediationAction]:
        """Return all registered actions in insertion order."""
        return list(self._actions.values())

    def is_registered(self, action_id: str) -> bool:
        """Check whether an action_id is registered."""
        return action_id in self._actions

    def count(self) -> int:
        """Return the number of registered actions."""
        return len(self._actions)

    def validate_against_catalog(self) -> list[str]:
        """Validate all registered actions against the catalog.

        Returns a list of error strings.  Empty list means all actions
        are consistent with the catalog.
        """
        from app.remediation.catalog import get_catalog_entry

        errors: list[str] = []
        for action_id, action in self._actions.items():
            entry = get_catalog_entry(action_id)
            if entry is None:
                errors.append(
                    f"Registered action '{action_id}' is not in the catalog."
                )
                continue
            if action.implementation_status != entry.implementation_status:
                errors.append(
                    f"Action '{action_id}' implementation_status mismatch: "
                    f"registry={action.implementation_status.value}, "
                    f"catalog={entry.implementation_status.value}."
                )
            if action.blast_radius != entry.blast_radius:
                errors.append(
                    f"Action '{action_id}' blast_radius mismatch: "
                    f"registry={action.blast_radius.value}, "
                    f"catalog={entry.blast_radius.value}."
                )
            if action.eligibility != entry.eligibility:
                errors.append(
                    f"Action '{action_id}' eligibility mismatch: "
                    f"registry={action.eligibility.value}, "
                    f"catalog={entry.eligibility.value}."
                )
        return errors


def validate_parameters(
    parameters: dict[str, Any],
    schema: ParameterSchema,
) -> list[str]:
    """Validate parameters against a schema.

    Returns a list of error strings.  Empty list means valid.
    """
    errors: list[str] = []
    all_allowed = schema.required | schema.optional

    # Check for unknown parameters
    unknown = set(parameters.keys()) - all_allowed
    if unknown:
        errors.append(f"Unknown parameters: {', '.join(sorted(unknown))}")

    # Check for missing required parameters
    missing = schema.required - set(parameters.keys())
    if missing:
        errors.append(f"Missing required parameters: {', '.join(sorted(missing))}")

    # Check types
    for name, expected_type in schema.types.items():
        if name in parameters:
            value = parameters[name]
            type_map = {
                "str": str,
                "int": int,
                "float": float,
                "bool": bool,
                "list": list,
                "dict": dict,
            }
            expected = type_map.get(expected_type)
            if expected is not None and not isinstance(value, expected):
                errors.append(
                    f"Parameter '{name}' must be {expected_type}, "
                    f"got {type(value).__name__}."
                )

    # Check allowed values
    for name, allowed in schema.values.items():
        if name in parameters and parameters[name] not in allowed:
            errors.append(
                f"Parameter '{name}' value '{parameters[name]}' "
                f"is not in allowed values: {sorted(allowed)}."
            )

    return errors


def create_default_registry() -> ActionRegistry:
    """Create a registry with all permitted remediation actions.

    Includes demo/no-op actions and the first real action (user_temp_quarantine).
    Demo actions are explicitly marked category="demo/test".
    """
    registry = ActionRegistry()

    registry.register(
        RemediationAction(
            action_id="demo.noop.print_message",
            name="Print a message (no-op)",
            description=(
                "A demonstration action that simulates printing a message. "
                "It performs no real I/O and modifies nothing."
            ),
            risk_level=RiskLevel.LOW,
            target="Console output (simulated)",
            reason="Framework testing only.",
            reversible=True,
            preview="Would print a confirmation message to stdout (simulated).",
            idempotent=True,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            blast_radius=BlastRadius.SINGLE_FILE,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.ELIGIBLE,
            category="demo/test",
        ),
        parameter_schema=ParameterSchema(
            required={"message"},
            optional={"level"},
            types={"message": "str", "level": "str"},
            values={"level": {"info", "warning", "error"}},
        ),
    )

    registry.register(
        RemediationAction(
            action_id="demo.noop.report_status",
            name="Report system status (no-op)",
            description=(
                "A demonstration action that simulates reporting system "
                "status.  It performs no real checks and modifies nothing."
            ),
            risk_level=RiskLevel.LOW,
            target="System status (simulated)",
            reason="Framework testing only.",
            reversible=True,
            preview="Would report current system status (simulated).",
            idempotent=True,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            blast_radius=BlastRadius.SINGLE_FILE,
            rollback_category=RollbackCategory.NOT_APPLICABLE,
            eligibility=EligibilityStatus.ELIGIBLE,
            category="demo/test",
        ),
        parameter_schema=ParameterSchema(
            required=set(),
            optional={"category"},
            types={"category": "str"},
        ),
    )

    # --- First real remediation action ---
    registry.register(
        RemediationAction(
            action_id="user_temp_quarantine",
            name="Quarantine old temporary files",
            description=(
                "Moves temporary files older than the configured age threshold "
                "from the current user's TEMP directory into an application-managed "
                "quarantine directory.  Files are NEVER permanently deleted.  "
                "Quarantined files can be restored via rollback."
            ),
            risk_level=RiskLevel.MEDIUM,
            target="User TEMP directory (per-user, not system temp)",
            reason="Reclaim disk space by quarantining stale temporary files.",
            requires_admin=False,
            reversible=True,
            preview=(
                "Would scan the user TEMP directory and move files older than "
                "the age threshold into quarantine.  Files are moved, not deleted."
            ),
            idempotent=True,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            blast_radius=BlastRadius.USER_DIRECTORY,
            rollback_category=RollbackCategory.SHUTIL_MOVE_RESTORE,
            eligibility=EligibilityStatus.ELIGIBLE,
            category="cleanup",
        ),
        parameter_schema=ParameterSchema(
            required=set(),
            optional={"age_days"},
            types={"age_days": "int"},
        ),
    )

    # --- disk.cleanup_temp: policy-driven safe temp cleanup ---
    registry.register(
        RemediationAction(
            action_id="disk.cleanup_temp",
            name="Safe temp cleanup (quarantine)",
            description=(
                "Quarantines temporary files older than age threshold.  "
                "Files are moved to quarantine (NEVER permanently deleted).  "
                "Rollback available.  Enforces MAX_FILES_PER_EXECUTION=500."
            ),
            risk_level=RiskLevel.MEDIUM,
            target="User TEMP directory (per-user, not system temp)",
            reason="Reclaim disk space by quarantining stale temporary files.",
            requires_admin=False,
            reversible=True,
            preview=(
                "Would scan the user TEMP directory and move files older than "
                "the age threshold into quarantine.  Files are moved, not deleted."
            ),
            idempotent=True,
            implementation_status=ImplementationStatus.IMPLEMENTED,
            blast_radius=BlastRadius.USER_DIRECTORY,
            rollback_category=RollbackCategory.SHUTIL_MOVE_RESTORE,
            eligibility=EligibilityStatus.ELIGIBLE,
            category="cleanup",
        ),
        parameter_schema=ParameterSchema(
            required=set(),
            optional={"age_days"},
            types={"age_days": "int"},
            values={"age_days": set(range(7, 366))},
        ),
    )

    return registry
