"""Action Executor abstraction -- simulation and quarantine execution."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.remediation.action import RemediationAction
from app.remediation.audit import AuditRecord, AuditStatus, AuditStore, _now
from app.remediation.confirmation import (
    ConfirmationToken,
    ConfirmationRequiredError,
    consume_confirmation,
)
from app.remediation.registry import ActionRegistry
from app.remediation.validation import ValidationResult


@dataclass(frozen=True)
class ExecutionResult:
    """Structured result of an action execution attempt.

    Attributes:
        action_id: The action that was executed.
        success: Whether the execution succeeded.
        simulated: Whether this was a simulation.
        rollback_available: Whether rollback is available for this action.
        audit_record_id: ID of the audit record created for this execution.
        message: Human-readable outcome description.
        error_message: Error description if execution failed.
        details: Additional structured details (e.g. quarantine result).
    """

    action_id: str
    success: bool
    simulated: bool = True
    rollback_available: bool = False
    audit_record_id: int | None = None
    message: str = ""
    error_message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class ExecutionDeniedError(Exception):
    """Raised when execution is denied by the safety framework."""


class BaseExecutor(ABC):
    """Abstract base for all executors.

    Subclasses must implement ``_do_execute()``.  The base class
    handles confirmation consumption, audit record creation, and
    lifecycle management.
    """

    def execute(
        self,
        action: RemediationAction,
        token: ConfirmationToken,
        validation: ValidationResult,
        registry: ActionRegistry,
        audit_store: AuditStore,
    ) -> ExecutionResult:
        """Execute an action through a controlled boundary.

        Requirements:
            1. ValidationResult must be valid.
            2. Action must be registered.
            3. Confirmation token must be valid and unconsumed.
            4. Token is consumed (single-use).
        """
        # 1. Enforce validation
        if not validation.valid:
            raise ExecutionDeniedError(
                f"Execution denied: validation failed with "
                f"{len(validation.errors)} error(s): "
                + "; ".join(validation.errors[:3])
            )

        # 2. Re-check registry
        if not registry.is_registered(action.action_id):
            raise ExecutionDeniedError(
                f"Execution denied: action '{action.action_id}' "
                "is not registered."
            )

        # 3. Consume confirmation (validates + marks as used)
        consumed_token = consume_confirmation(action, token)

        # 4. Create audit record
        audit_record = AuditRecord(
            action_id=action.action_id,
            finding_id=action.finding_id,
            discovery_run_id=action.discovery_run_id,
            status=AuditStatus.EXECUTING.value,
            risk_level=action.risk_level.value,
            target=action.target,
            reason=action.reason,
            rollback_available=action.reversible,
        )
        record_id = audit_store.create_record(audit_record)

        # 5. Delegate to subclass
        try:
            result = self._do_execute(action, consumed_token, record_id)
            # Determine final status based on result
            if result.success:
                final_status = AuditStatus.SUCCEEDED
            elif result.details.get("files_moved", 0) > 0:
                # Moved files but something went wrong (persistence errors, etc.)
                final_status = AuditStatus.PARTIALLY_SUCCEEDED
            else:
                final_status = AuditStatus.FAILED

            audit_store.update_status(
                record_id,
                final_status,
                result_summary=result.message,
                executed_at=_now(),
            )
            return result
        except Exception as exc:
            audit_store.update_status(
                record_id,
                AuditStatus.FAILED,
                error_message=str(exc),
                executed_at=_now(),
            )
            return ExecutionResult(
                action_id=action.action_id,
                success=False,
                simulated=True,
                audit_record_id=record_id,
                message=f"Execution failed: {exc}",
                error_message=str(exc),
            )

    @abstractmethod
    def _do_execute(
        self,
        action: RemediationAction,
        token: ConfirmationToken,
        audit_record_id: int,
    ) -> ExecutionResult:
        """Subclass implementation of the actual execution."""
        ...


class SimulationExecutor(BaseExecutor):
    """Executor that simulates execution without modifying the system.

    Used for demo/no-op actions.
    """

    def _do_execute(
        self,
        action: RemediationAction,
        token: ConfirmationToken,
        audit_record_id: int,
    ) -> ExecutionResult:
        message = (
            f"[SIMULATED] Action '{action.action_id}' executed successfully. "
            f"No real system changes were made."
        )
        return ExecutionResult(
            action_id=action.action_id,
            success=True,
            simulated=True,
            rollback_available=action.reversible,
            audit_record_id=audit_record_id,
            message=message,
        )


class QuarantineExecutor(BaseExecutor):
    """Executor that quarantines eligible temporary files.

    This is the first real remediation executor.  It moves files into
    a quarantine directory and creates audit + quarantine records.
    """

    def __init__(self, quarantine_store: Any) -> None:
        self._quarantine_store = quarantine_store

    def _do_execute(
        self,
        action: RemediationAction,
        token: ConfirmationToken,
        audit_record_id: int,
    ) -> ExecutionResult:
        if action.action_id == "disk.cleanup_temp":
            return self._execute_cleanup_temp(action, token, audit_record_id)
        return self._execute_quarantine(action, token, audit_record_id)

    def _execute_quarantine(
        self,
        action: RemediationAction,
        token: ConfirmationToken,
        audit_record_id: int,
    ) -> ExecutionResult:
        from app.remediation.quarantine import (
            execute_quarantine,
            get_user_temp_dir,
        )

        age_days = action.parameters.get("age_days", 7)
        temp_root = get_user_temp_dir()
        if temp_root is None:
            return ExecutionResult(
                action_id=action.action_id,
                success=False,
                simulated=False,
                audit_record_id=audit_record_id,
                message="Cannot determine user TEMP directory.",
                error_message="Cannot determine user TEMP directory.",
            )

        qresult = execute_quarantine(
            temp_root=temp_root,
            age_threshold_days=age_days,
        )

        # Create quarantine records for moved files
        record_ids: list[int] = []
        if qresult.files_moved > 0:
            from app.remediation.quarantine import get_quarantine_dir
            from app.remediation.quarantine_store import QuarantineRecord
            from pathlib import Path
            import time

            quarantine_dir = get_quarantine_dir()
            for entry in quarantine_dir.iterdir():
                if entry.is_file():
                    # Check if this file was just moved (within last 5 seconds)
                    try:
                        stat = entry.stat()
                        if time.time() - stat.st_mtime < 5:
                            record = QuarantineRecord(
                                action_id=action.action_id,
                                audit_record_id=audit_record_id,
                                original_path="",  # We don't track this in move result
                                quarantine_path=str(entry),
                                original_size=stat.st_size,
                                original_mtime=str(stat.st_mtime),
                            )
                            rid = self._quarantine_store.create_record(record)
                            record_ids.append(rid)
                    except (OSError, PermissionError):
                        pass

        success = qresult.files_failed == 0 and qresult.files_moved > 0
        message = (
            f"Quarantine complete: {qresult.files_moved} files moved, "
            f"{qresult.files_skipped} skipped, {qresult.files_failed} failed. "
            f"Total bytes moved: {qresult.total_bytes_moved}."
        )

        return ExecutionResult(
            action_id=action.action_id,
            success=success,
            simulated=False,
            rollback_available=True,
            audit_record_id=audit_record_id,
            message=message,
            details={
                "files_examined": qresult.files_examined,
                "files_eligible": qresult.files_eligible,
                "files_moved": qresult.files_moved,
                "files_skipped": qresult.files_skipped,
                "files_failed": qresult.files_failed,
                "total_bytes_moved": qresult.total_bytes_moved,
                "failure_reasons": qresult.failure_reasons,
                "quarantine_record_ids": record_ids,
                "quarantine_dir": qresult.quarantine_dir,
            },
        )

    def _execute_cleanup_temp(
        self,
        action: RemediationAction,
        token: ConfirmationToken,
        audit_record_id: int,
    ) -> ExecutionResult:
        from app.remediation.cleanup_temp import execute_cleanup

        age_days = action.parameters.get("age_days", 30)

        cresult = execute_cleanup(age_days=age_days)

        # Create quarantine records from authoritative MoveRecords
        # (created immediately after each successful shutil.move)
        record_ids: list[int] = []
        persistence_errors: list[str] = []

        if cresult.move_records:
            from app.remediation.quarantine_store import QuarantineRecord

            for mr in cresult.move_records:
                try:
                    record = QuarantineRecord(
                        action_id=action.action_id,
                        audit_record_id=audit_record_id,
                        original_path=mr.original_path,
                        quarantine_path=mr.quarantine_path,
                        original_size=mr.original_size,
                        original_mtime=mr.original_mtime_iso,
                    )
                    rid = self._quarantine_store.create_record(record)
                    record_ids.append(rid)
                except (OSError, PermissionError) as exc:
                    # Move succeeded but record creation failed — distinct error
                    msg = (
                        f"Move succeeded but quarantine record creation failed "
                        f"for {mr.original_path}: {exc}"
                    )
                    persistence_errors.append(msg)

        # Determine status from actual outcomes
        files_moved = cresult.files_moved
        files_failed = cresult.files_failed
        files_skipped = cresult.files_skipped
        persistence_failures = len(persistence_errors)

        if files_moved == 0:
            success = False
        elif files_failed > 0 or persistence_failures > 0:
            success = False
        else:
            success = True

        message = (
            f"Temp cleanup complete: {files_moved} files quarantined, "
            f"{files_skipped} skipped, {files_failed} failed.  "
            f"Total bytes moved: {cresult.bytes_moved}."
        )

        if persistence_failures > 0:
            message += (
                f"  WARNING: {persistence_failures} quarantine record(s) "
                f"could not be persisted — rollback may be unavailable "
                f"for those files."
            )

        details = {
            "files_examined": cresult.files_examined,
            "candidates": cresult.candidates,
            "files_moved": files_moved,
            "files_skipped": files_skipped,
            "files_failed": files_failed,
            "bytes_moved": cresult.bytes_moved,
            "skip_reasons": cresult.skip_reasons,
            "failure_reasons": cresult.failure_reasons,
            "quarantine_record_ids": record_ids,
            "quarantine_dir": cresult.quarantine_dir,
            "persistence_errors": persistence_errors,
            "persistence_failures": persistence_failures,
        }

        return ExecutionResult(
            action_id=action.action_id,
            success=success,
            simulated=False,
            rollback_available=files_moved > 0,
            audit_record_id=audit_record_id,
            message=message,
            error_message=(
                "; ".join(persistence_errors)
                if persistence_errors
                else None
            ),
            details=details,
        )


# Module-level convenience functions

_sim_executor = SimulationExecutor()


def execute_action(
    action: RemediationAction,
    token: ConfirmationToken,
    validation: ValidationResult,
    registry: ActionRegistry,
    audit_store: AuditStore,
) -> ExecutionResult:
    """Execute an action through the simulation executor.

    This is the default execution path for demo/no-op actions.
    """
    return _sim_executor.execute(
        action, token, validation, registry, audit_store
    )
