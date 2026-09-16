"""Remediation safety framework -- including real quarantine capability."""

from __future__ import annotations

from app.remediation.action import RiskLevel, RemediationAction
from app.remediation.registry import (
    ActionRegistry,
    ParameterSchema,
    validate_parameters,
)
from app.remediation.preview import PreviewResult, preview_action
from app.remediation.confirmation import (
    ConfirmationToken,
    ConfirmationRequiredError,
    ConfirmationReuseError,
    confirm_action,
    consume_confirmation,
    require_confirmation,
)
from app.remediation.validation import validate_action, ValidationResult
from app.remediation.audit import (
    AuditRecord,
    AuditStatus,
    AuditStore,
    InvalidTransitionError,
)
from app.remediation.rollback import (
    RollbackCapability,
    BackupNotImplementedError,
    RollbackNotImplementedError,
    rollback_quarantine_file,
)
from app.remediation.permissions import check_admin_privileges
from app.remediation.idempotency import Idempotency
from app.remediation.executor import (
    BaseExecutor,
    SimulationExecutor,
    QuarantineExecutor,
    ExecutionResult,
    ExecutionDeniedError,
    execute_action,
)
from app.remediation.quarantine_store import QuarantineStore, QuarantineRecord
from app.remediation.quarantine import (
    QuarantinePlan,
    QuarantineResult,
    EligibleFile,
    preview_quarantine,
    execute_quarantine,
    rollback_quarantine,
    get_user_temp_dir,
    get_quarantine_dir,
)
