"""Audit Log -- SQLite table and operations for remediation actions."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class AuditStatus(str, Enum):
    """Lifecycle statuses for an audit record."""

    PROPOSED = "proposed"
    PREVIEWED = "previewed"
    CONFIRMED = "confirmed"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    PARTIALLY_SUCCEEDED = "partially_succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


# Legal state transitions: from -> set of allowed destinations.
_LEGAL_TRANSITIONS: dict[str, set[str]] = {
    AuditStatus.PROPOSED.value: {
        AuditStatus.PREVIEWED.value,
        AuditStatus.CANCELLED.value,
    },
    AuditStatus.PREVIEWED.value: {
        AuditStatus.CONFIRMED.value,
        AuditStatus.CANCELLED.value,
    },
    AuditStatus.CONFIRMED.value: {
        AuditStatus.EXECUTING.value,
        AuditStatus.CANCELLED.value,
    },
    AuditStatus.EXECUTING.value: {
        AuditStatus.SUCCEEDED.value,
        AuditStatus.PARTIALLY_SUCCEEDED.value,
        AuditStatus.FAILED.value,
    },
    # ROLLED_BACK can transition from SUCCEEDED or PARTIALLY_SUCCEEDED
    AuditStatus.SUCCEEDED.value: {
        AuditStatus.ROLLED_BACK.value,
    },
    AuditStatus.PARTIALLY_SUCCEEDED.value: {
        AuditStatus.ROLLED_BACK.value,
    },
    # Terminal states -- no transitions out
    AuditStatus.FAILED.value: set(),
    AuditStatus.CANCELLED.value: set(),
    AuditStatus.ROLLED_BACK.value: set(),
}


class InvalidTransitionError(Exception):
    """Raised when an audit status transition is not allowed."""


@dataclass(frozen=True)
class AuditRecord:
    """A single audit log entry.

    Attributes:
        id: Database primary key (set after insertion).
        action_id: The registered action identifier.
        action_version: Version of the action definition at time of execution.
        implementation_status: Implementation status at time of execution.
        finding_id: Originating finding ID, if any.
        discovery_run_id: Originating discovery run ID, if any.
        requested_at: When the action was first proposed.
        executed_at: When execution was attempted (if ever).
        status: Current lifecycle status.
        risk_level: Risk classification at time of proposal.
        target: Description of the target resource.
        reason: Why the action was proposed.
        result_summary: Human-readable outcome description.
        rollback_available: Whether rollback was available.
        error_message: Error description if the action failed.
    """

    action_id: str
    action_version: str = "1"
    implementation_status: str = "not_implemented"
    finding_id: int | None = None
    discovery_run_id: int | None = None
    requested_at: str | None = None
    executed_at: str | None = None
    status: str = AuditStatus.PROPOSED.value
    risk_level: str = "low"
    target: str = ""
    reason: str = ""
    result_summary: str = ""
    rollback_available: bool = False
    error_message: str | None = None
    id: int | None = None


AUDIT_TABLE = """
CREATE TABLE IF NOT EXISTS remediation_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL,
    action_version TEXT NOT NULL DEFAULT '1',
    implementation_status TEXT NOT NULL DEFAULT 'not_implemented',
    finding_id INTEGER,
    discovery_run_id INTEGER,
    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    executed_at TEXT,
    status TEXT NOT NULL DEFAULT 'proposed',
    risk_level TEXT NOT NULL DEFAULT 'low',
    target TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    result_summary TEXT NOT NULL DEFAULT '',
    rollback_available INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);
"""

AUDIT_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_audit_action_id
ON remediation_audit(action_id);
CREATE INDEX IF NOT EXISTS idx_audit_status
ON remediation_audit(status);
CREATE INDEX IF NOT EXISTS idx_audit_discovery_run_id
ON remediation_audit(discovery_run_id);
"""


class AuditStore:
    """SQLite-backed audit log for remediation actions.

    This is a standalone audit log.  It does NOT create copies of
    discovery_runs or findings tables.  Foreign key integrity is
    managed at the application layer.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._initialize()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.db_path)
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='remediation_audit'"
            )
            if cursor.fetchone() is None:
                connection.executescript(AUDIT_TABLE)
            else:
                # Migration: add action_version and implementation_status
                # columns if they don't exist (backward compatible).
                cursor = connection.execute(
                    "PRAGMA table_info(remediation_audit)"
                )
                columns = {row[1] for row in cursor.fetchall()}
                if "action_version" not in columns:
                    connection.execute(
                        "ALTER TABLE remediation_audit "
                        "ADD COLUMN action_version TEXT NOT NULL DEFAULT '1'"
                    )
                if "implementation_status" not in columns:
                    connection.execute(
                        "ALTER TABLE remediation_audit "
                        "ADD COLUMN implementation_status "
                        "TEXT NOT NULL DEFAULT 'not_implemented'"
                    )
            connection.executescript(AUDIT_INDEXES)

    def create_record(self, record: AuditRecord) -> int:
        """Insert a new audit record.  Returns the database ID."""
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO remediation_audit("
                "  action_id, action_version, implementation_status,"
                "  finding_id, discovery_run_id, requested_at,"
                "  executed_at, status, risk_level, target, reason,"
                "  result_summary, rollback_available, error_message"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.action_id,
                    record.action_version,
                    record.implementation_status,
                    record.finding_id,
                    record.discovery_run_id,
                    record.requested_at or _now(),
                    record.executed_at,
                    record.status,
                    record.risk_level,
                    record.target,
                    record.reason,
                    record.result_summary,
                    1 if record.rollback_available else 0,
                    record.error_message,
                ),
            )
            return int(cursor.lastrowid)

    def update_status(
        self,
        record_id: int,
        status: AuditStatus,
        *,
        result_summary: str | None = None,
        error_message: str | None = None,
        executed_at: str | None = None,
    ) -> None:
        """Update the status of an audit record.

        Enforces legal state transitions.  Raises InvalidTransitionError
        if the transition is not allowed.
        """
        with self._connect() as connection:
            # Load current status
            cursor = connection.execute(
                "SELECT status FROM remediation_audit WHERE id = ?",
                (record_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError(f"Audit record {record_id} not found.")

            current_status = row[0]
            allowed = _LEGAL_TRANSITIONS.get(current_status, set())

            if status.value not in allowed:
                raise InvalidTransitionError(
                    f"Cannot transition from '{current_status}' to "
                    f"'{status.value}'.  Allowed transitions: "
                    f"{sorted(allowed) if allowed else '(none -- terminal state)'}."
                )

            fields = ["status = ?"]
            values: list[Any] = [status.value]

            if result_summary is not None:
                fields.append("result_summary = ?")
                values.append(result_summary)
            if error_message is not None:
                fields.append("error_message = ?")
                values.append(error_message)
            if executed_at is not None:
                fields.append("executed_at = ?")
                values.append(executed_at)

            values.append(record_id)
            connection.execute(
                f"UPDATE remediation_audit SET {', '.join(fields)} WHERE id = ?",
                values,
            )

    def get_record(self, record_id: int) -> AuditRecord | None:
        """Load a single audit record by ID."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT id, action_id, action_version, implementation_status,"
                "  finding_id, discovery_run_id,"
                "  requested_at, executed_at, status, risk_level,"
                "  target, reason, result_summary, rollback_available,"
                "  error_message "
                "FROM remediation_audit WHERE id = ?",
                (record_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return _row_to_record(row)

    def list_records(
        self,
        *,
        action_id: str | None = None,
        status: AuditStatus | None = None,
        discovery_run_id: int | None = None,
    ) -> list[AuditRecord]:
        """Query audit records with optional filters."""
        conditions: list[str] = []
        params: list[Any] = []

        if action_id is not None:
            conditions.append("action_id = ?")
            params.append(action_id)
        if status is not None:
            conditions.append("status = ?")
            params.append(status.value)
        if discovery_run_id is not None:
            conditions.append("discovery_run_id = ?")
            params.append(discovery_run_id)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

        with self._connect() as connection:
            cursor = connection.execute(
                f"SELECT id, action_id, action_version,"
                f"  implementation_status, finding_id, discovery_run_id,"
                f"  requested_at, executed_at, status, risk_level,"
                f"  target, reason, result_summary, rollback_available,"
                f"  error_message "
                f"FROM remediation_audit{where} ORDER BY id",
                params,
            )
            return [_row_to_record(row) for row in cursor.fetchall()]


def _now() -> str:
    """Current UTC timestamp in ISO format."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _row_to_record(row: tuple) -> AuditRecord:
    """Convert a database row to an AuditRecord."""
    return AuditRecord(
        id=row[0],
        action_id=row[1],
        action_version=row[2],
        implementation_status=row[3],
        finding_id=row[4],
        discovery_run_id=row[5],
        requested_at=row[6],
        executed_at=row[7],
        status=row[8],
        risk_level=row[9],
        target=row[10],
        reason=row[11],
        result_summary=row[12],
        rollback_available=bool(row[13]),
        error_message=row[14],
    )
