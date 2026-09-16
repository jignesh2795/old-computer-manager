"""Quarantine record storage -- SQLite table for quarantined file metadata."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class QuarantineRecord:
    """Metadata for a single quarantined file.

    Attributes:
        id: Database primary key.
        action_id: The action that quarantined this file.
        audit_record_id: Linked audit record.
        original_path: Where the file was before quarantine.
        quarantine_path: Where the file is now.
        original_size: File size in bytes at quarantine time.
        original_mtime: Modification time at quarantine time (ISO format).
        quarantined_at: When the file was quarantined.
        restored: Whether this file has been restored.
        restored_at: When the file was restored, if ever.
        error_message: Error during quarantine, if any.
    """

    action_id: str
    audit_record_id: int | None = None
    original_path: str = ""
    quarantine_path: str = ""
    original_size: int = 0
    original_mtime: str = ""
    quarantined_at: str = ""
    restored: bool = False
    restored_at: str | None = None
    error_message: str | None = None
    id: int | None = None


class QuarantineStore:
    """SQLite-backed storage for quarantine records.

    This store manages the metadata for quarantined files.  It does NOT
    create or manage the quarantine directory itself -- that is the
    responsibility of the quarantine module.
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
                "AND name='quarantine_records'"
            )
            if cursor.fetchone() is None:
                connection.execute(
                    "CREATE TABLE quarantine_records ("
                    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "    action_id TEXT NOT NULL,"
                    "    audit_record_id INTEGER,"
                    "    original_path TEXT NOT NULL,"
                    "    quarantine_path TEXT NOT NULL,"
                    "    original_size INTEGER NOT NULL,"
                    "    original_mtime TEXT NOT NULL,"
                    "    quarantined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                    "    restored INTEGER NOT NULL DEFAULT 0,"
                    "    restored_at TEXT,"
                    "    error_message TEXT"
                    ")"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_quarantine_audit_id "
                    "ON quarantine_records(audit_record_id)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_quarantine_action_id "
                    "ON quarantine_records(action_id)"
                )

    def create_record(self, record: QuarantineRecord) -> int:
        """Insert a new quarantine record.  Returns the database ID."""
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO quarantine_records("
                "  action_id, audit_record_id, original_path, quarantine_path,"
                "  original_size, original_mtime, quarantined_at, restored,"
                "  restored_at, error_message"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.action_id,
                    record.audit_record_id,
                    record.original_path,
                    record.quarantine_path,
                    record.original_size,
                    record.original_mtime,
                    record.quarantined_at or _now(),
                    1 if record.restored else 0,
                    record.restored_at,
                    record.error_message,
                ),
            )
            return int(cursor.lastrowid)

    def mark_restored(self, record_id: int) -> None:
        """Mark a quarantine record as restored."""
        with self._connect() as connection:
            connection.execute(
                "UPDATE quarantine_records SET restored = 1, restored_at = ? "
                "WHERE id = ?",
                (_now(), record_id),
            )

    def get_record(self, record_id: int) -> QuarantineRecord | None:
        """Load a single quarantine record by ID."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT id, action_id, audit_record_id, original_path,"
                "  quarantine_path, original_size, original_mtime,"
                "  quarantined_at, restored, restored_at, error_message "
                "FROM quarantine_records WHERE id = ?",
                (record_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return _row_to_record(row)

    def get_by_audit_record(self, audit_record_id: int) -> QuarantineRecord | None:
        """Load a quarantine record by its audit record ID."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT id, action_id, audit_record_id, original_path,"
                "  quarantine_path, original_size, original_mtime,"
                "  quarantined_at, restored, restored_at, error_message "
                "FROM quarantine_records WHERE audit_record_id = ?",
                (audit_record_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return _row_to_record(row)

    def list_records(
        self,
        *,
        action_id: str | None = None,
        audit_record_id: int | None = None,
        restored: bool | None = None,
    ) -> list[QuarantineRecord]:
        """Query quarantine records with optional filters."""
        conditions: list[str] = []
        params: list[Any] = []

        if action_id is not None:
            conditions.append("action_id = ?")
            params.append(action_id)
        if audit_record_id is not None:
            conditions.append("audit_record_id = ?")
            params.append(audit_record_id)
        if restored is not None:
            conditions.append("restored = ?")
            params.append(1 if restored else 0)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

        with self._connect() as connection:
            cursor = connection.execute(
                f"SELECT id, action_id, audit_record_id, original_path,"
                f"  quarantine_path, original_size, original_mtime,"
                f"  quarantined_at, restored, restored_at, error_message "
                f"FROM quarantine_records{where} ORDER BY id",
                params,
            )
            return [_row_to_record(row) for row in cursor.fetchall()]


def _now() -> str:
    """Current UTC timestamp in ISO format."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _row_to_record(row: tuple) -> QuarantineRecord:
    """Convert a database row to a QuarantineRecord."""
    return QuarantineRecord(
        id=row[0],
        action_id=row[1],
        audit_record_id=row[2],
        original_path=row[3],
        quarantine_path=row[4],
        original_size=row[5],
        original_mtime=row[6],
        quarantined_at=row[7],
        restored=bool(row[8]),
        restored_at=row[9],
        error_message=row[10],
    )
