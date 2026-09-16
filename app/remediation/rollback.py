"""Backup / Rollback abstractions -- including real quarantine rollback."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class RollbackAvailability(str, Enum):
    """Whether rollback is possible for an action.

    AVAILABLE: Rollback is implemented and tested for this action.
    NOT_AVAILABLE: Rollback is not implemented for this action.
    UNKNOWN: The action does not declare rollback capability.
    """

    AVAILABLE = "available"
    NOT_AVAILABLE = "not_available"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RollbackCapability:
    """Describes the rollback properties of an action.

    Attributes:
        availability: Whether rollback is implemented.
        description: Human-readable explanation of rollback behavior.
        backup_required: Whether a backup must be created before execution.
        estimated_backup_size_bytes: Rough estimate of backup size (0 = unknown).
    """

    availability: RollbackAvailability = RollbackAvailability.UNKNOWN
    description: str = ""
    backup_required: bool = False
    estimated_backup_size_bytes: int = 0


class BackupNotImplementedError(Exception):
    """Raised when backup is attempted but not implemented."""


class RollbackNotImplementedError(Exception):
    """Raised when rollback is attempted but not implemented."""


def get_rollback_capability(
    reversible: bool,
    *,
    description: str = "",
    backup_required: bool = False,
) -> RollbackCapability:
    """Derive rollback capability from an action's properties."""
    if reversible:
        return RollbackCapability(
            availability=RollbackAvailability.AVAILABLE,
            description=description or "Action claims reversibility.",
            backup_required=backup_required,
        )
    return RollbackCapability(
        availability=RollbackAvailability.NOT_AVAILABLE,
        description=description or "Action is not reversible.",
    )


def prepare_backup(action_id: str) -> None:
    """Prepare a backup before action execution.

    Generic backup is not implemented.  Action-specific backup (e.g.
    quarantine) is handled by the action executor.
    """
    raise BackupNotImplementedError(
        f"Generic backup is not implemented for action '{action_id}'. "
        "Action-specific backup is handled by the executor."
    )


def execute_rollback(backup_id: str) -> None:
    """Execute a rollback from a backup.

    Generic rollback is not implemented.  Action-specific rollback
    (e.g. quarantine restore) is handled by the action module.
    """
    raise RollbackNotImplementedError(
        f"Generic rollback is not implemented for backup '{backup_id}'. "
        "Action-specific rollback is handled by the action module."
    )


def rollback_quarantine_file(
    quarantine_store: Any,
    quarantine_record_id: int,
    *,
    overwrite: bool = False,
) -> tuple[bool, str]:
    """Restore a quarantined file to its original location.

    This is the action-specific rollback for user_temp_quarantine.

    Args:
        quarantine_store: QuarantineStore instance.
        quarantine_record_id: ID of the quarantine record.
        overwrite: Whether to overwrite an existing file at the
            original path.

    Returns:
        (success, message)
    """
    from app.remediation.quarantine import rollback_quarantine

    return rollback_quarantine(
        quarantine_record_id,
        quarantine_store,
        overwrite=overwrite,
    )
