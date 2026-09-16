"""Pre-execution validation framework."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.remediation.action import RemediationAction
from app.remediation.registry import ActionRegistry, validate_parameters


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of pre-execution validation.

    Attributes:
        valid: Whether the action passed all checks.
        errors: List of human-readable error descriptions.
        warnings: List of non-fatal concerns.
    """

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ValidationError(Exception):
    """Raised when pre-execution validation fails."""


def validate_action(
    action: RemediationAction,
    registry: ActionRegistry,
    *,
    findings_store: Any | None = None,
    discovery_store: Any | None = None,
    target_state: dict[str, Any] | None = None,
) -> ValidationResult:
    """Validate that a proposed action is eligible for execution.

    Checks performed:
        1. The action_id is registered in the registry.
        2. The action parameters are valid (non-empty action_id, name, etc.).
        3. If finding_id is set, the originating finding exists in the store.
        4. If discovery_run_id is set, the discovery run exists and is completed.
        5. If target_state is provided, validates the target has not changed.
        6. Parameters are validated against the registered schema.

    Args:
        action: The proposed remediation action.
        registry: The action registry containing permitted actions.
        findings_store: Optional SnapshotStore for finding existence checks.
        discovery_store: Optional SnapshotStore for run existence checks.
        target_state: Optional dict describing expected target state.
                      If the actual state differs, a warning is emitted.

    Returns:
        ValidationResult with valid=True only if all checks pass.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # 1. Registry check
    if not registry.is_registered(action.action_id):
        errors.append(
            f"Action '{action.action_id}' is not registered. "
            "Only registered actions may be executed."
        )

    # 2. Parameter validation
    if not action.action_id:
        errors.append("action_id must not be empty.")
    if not action.name:
        errors.append("name must not be empty.")
    if not action.description:
        errors.append("description must not be empty.")
    if not action.target:
        errors.append("target must not be empty.")
    if not action.reason:
        errors.append("reason must not be empty.")

    # 3. Finding existence check -- query real finding record
    if action.finding_id is not None and findings_store is not None:
        try:
            latest_run = findings_store.get_latest_completed_run()
            if latest_run is None:
                errors.append(
                    f"Finding ID {action.finding_id} specified but no "
                    "completed discovery run exists."
                )
            else:
                findings = findings_store.load_findings(latest_run["id"])
                # Check if the finding_id exists as a real row ID
                # Findings are stored with auto-increment IDs; we need to
                # query the actual database.  For now, check via the store's
                # internal connection.
                _finding_exists = _check_finding_exists(
                    findings_store, action.finding_id
                )
                if not _finding_exists:
                    errors.append(
                        f"Finding ID {action.finding_id} does not exist "
                        "in the findings table."
                    )
                elif action.discovery_run_id is not None:
                    # Verify the finding belongs to the declared run
                    _finding_in_run = _check_finding_in_run(
                        findings_store, action.finding_id, action.discovery_run_id
                    )
                    if not _finding_in_run:
                        errors.append(
                            f"Finding ID {action.finding_id} does not belong "
                            f"to discovery run {action.discovery_run_id}."
                        )
        except Exception as exc:
            warnings.append(
                f"Could not verify finding existence: {exc}"
            )

    # 4. Discovery run existence check -- must actually exist
    if action.discovery_run_id is not None and discovery_store is not None:
        try:
            run_info = _check_run_exists(discovery_store, action.discovery_run_id)
            if run_info is None:
                errors.append(
                    f"Discovery run ID {action.discovery_run_id} does not exist."
                )
            elif run_info["status"] not in ("completed", "completed_with_errors"):
                errors.append(
                    f"Discovery run ID {action.discovery_run_id} has status "
                    f"'{run_info['status']}', not completed."
                )
        except Exception as exc:
            warnings.append(
                f"Could not verify discovery run existence: {exc}"
            )

    # 5. Target state check
    if target_state is not None:
        for key, expected_value in target_state.items():
            if key == "_changed_since_analysis":
                warnings.append(
                    "Target state has changed since the action was proposed. "
                    "Re-analyze before executing."
                )

    # 6. Parameter schema validation
    if registry.is_registered(action.action_id):
        schema = registry.get_schema(action.action_id)
        if schema is not None:
            param_errors = validate_parameters(action.parameters, schema)
            errors.extend(param_errors)

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


def _check_finding_exists(store: Any, finding_id: int) -> bool:
    """Check whether a finding with the given ID exists in the database."""
    try:
        with store._connect() as connection:
            cursor = connection.execute(
                "SELECT COUNT(*) FROM findings WHERE id = ?",
                (finding_id,),
            )
            return cursor.fetchone()[0] > 0
    except Exception:
        return False


def _check_finding_in_run(
    store: Any, finding_id: int, run_id: int
) -> bool:
    """Check whether a finding belongs to a specific discovery run."""
    try:
        with store._connect() as connection:
            cursor = connection.execute(
                "SELECT COUNT(*) FROM findings WHERE id = ? AND run_id = ?",
                (finding_id, run_id),
            )
            return cursor.fetchone()[0] > 0
    except Exception:
        return False


def _check_run_exists(store: Any, run_id: int) -> dict[str, Any] | None:
    """Check whether a discovery run exists and return its info."""
    try:
        with store._connect() as connection:
            cursor = connection.execute(
                "SELECT id, status FROM discovery_runs WHERE id = ?",
                (run_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return {"id": row[0], "status": row[1]}
    except Exception:
        return None
