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


@dataclass(frozen=True)
class ReconciliationIssue:
    """A quarantine consistency issue found during reconciliation.

    Attributes:
        issue_id: Stable identifier for this issue instance.
        issue_type: Category of inconsistency.
        quarantine_path: Path to the quarantine file, when known.
        record_id: Database record ID, when known.
        original_path: Original file path, when known.
        size: File size in bytes, when known.
        detected_at: ISO timestamp when this issue was detected.
        explanation: Human-readable explanation.
        recoverability: How this issue can be addressed.
        recommended_next_step: What a human should do.
    """

    issue_type: str
    issue_id: str = ""
    quarantine_path: str = ""
    record_id: int | None = None
    original_path: str = ""
    size: int = 0
    detected_at: str = ""
    explanation: str = ""
    recoverability: str = "unknown"
    recommended_next_step: str = ""


# Valid issue types
VALID_ISSUE_TYPES = frozenset({
    "valid_record",
    "file_without_record",
    "record_without_file",
    "empty_original_path",
    "duplicate_record",
    "invalid_record",
    "unexpected_quarantine_entry",
})

# Recovery classifications
RECOVERABILITY_CLASSIFICATIONS = frozenset({
    "recoverable",
    "requires_manual_review",
    "unrecoverable",
    "unknown",
})

# Known test artifact patterns (from first live test runs)
_TEST_ARTIFACT_PATTERNS = (
    "ocm-test-disposable-",
    "wct",  # Windows Compatibility Telemetry temp files
    "mat-debug-",  # MAT debug logs
    "jb.station.",  # JetBrains station files
    "jetbrainsd",  # JetBrains daemon files
    "_.ses",  # Session files
)


def _is_test_artifact(filename: str) -> bool:
    """Check if a filename matches known test-artifact patterns."""
    return any(pattern in filename for pattern in _TEST_ARTIFACT_PATTERNS)


def reconcile_quarantine(
    quarantine_dir: Path,
    store: QuarantineStore,
) -> ReconciliationReport:
    """Check quarantine consistency between filesystem and database.

    This function is READ-ONLY. It inspects the quarantine directory and
    database records but does NOT modify, move, delete, or restore any files.

    Identifies:
    - quarantine file with no matching record (orphaned file)
    - record with missing quarantine file (broken reference)
    - record with empty original_path (rollback impossible)
    - duplicate records for the same quarantine path
    - invalid records with missing required fields
    """
    from datetime import datetime, timezone

    detected_at = datetime.now(timezone.utc).isoformat()
    issues: list[ReconciliationIssue] = []
    issue_counter = 0

    def _next_issue_id() -> str:
        nonlocal issue_counter
        issue_counter += 1
        return f"rq-{issue_counter:04d}"

    # Load all non-restored records
    records = store.list_records(restored=False)

    # Build lookup: quarantine_path -> list of records
    records_by_qpath: dict[str, list[QuarantineRecord]] = {}
    for rec in records:
        records_by_qpath.setdefault(rec.quarantine_path, []).append(rec)

    # Scan quarantine directory
    scanned_files = 0
    file_without_record_count = 0
    duplicate_record_count = 0
    invalid_record_count = 0

    if quarantine_dir.exists():
        for entry in quarantine_dir.iterdir():
            if not entry.is_file():
                continue
            scanned_files += 1
            qpath = str(entry)

            matching_records = records_by_qpath.get(qpath, [])

            if not matching_records:
                # File exists but no record
                file_without_record_count += 1
                is_artifact = _is_test_artifact(entry.name)
                stat = entry.stat()

                if is_artifact:
                    explanation = (
                        f"Quarantine file '{entry.name}' has no database record. "
                        f"Matches known test-artifact naming pattern."
                    )
                    recoverability = "recoverable"
                    next_step = "Manual review recommended. File matches test-artifact pattern."
                else:
                    explanation = (
                        f"Quarantine file '{entry.name}' has no database record. "
                        f"Provenance unknown."
                    )
                    recoverability = "requires_manual_review"
                    next_step = "Manual review required to determine file provenance."

                issues.append(ReconciliationIssue(
                    issue_type="file_without_record",
                    issue_id=_next_issue_id(),
                    quarantine_path=qpath,
                    size=stat.st_size,
                    detected_at=detected_at,
                    explanation=explanation,
                    recoverability=recoverability,
                    recommended_next_step=next_step,
                ))
            else:
                # File has matching record(s)
                rec = matching_records[0]

                # Check for duplicate records
                if len(matching_records) > 1:
                    duplicate_record_count += 1
                    issues.append(ReconciliationIssue(
                        issue_type="duplicate_record",
                        issue_id=_next_issue_id(),
                        quarantine_path=qpath,
                        record_id=rec.id,
                        original_path=rec.original_path,
                        size=rec.original_size,
                        detected_at=detected_at,
                        explanation=(
                            f"Multiple records ({len(matching_records)}) exist for "
                            f"quarantine file '{entry.name}'."
                        ),
                        recoverability="requires_manual_review",
                        recommended_next_step=(
                            "Manual review required to determine which record is authoritative."
                        ),
                    ))

                # Check for empty original_path
                if not rec.original_path:
                    issues.append(ReconciliationIssue(
                        issue_type="empty_original_path",
                        issue_id=_next_issue_id(),
                        quarantine_path=qpath,
                        record_id=rec.id,
                        size=rec.original_size,
                        detected_at=detected_at,
                        explanation=(
                            f"Record #{rec.id} has empty original_path. "
                            f"Rollback to original location is impossible."
                        ),
                        recoverability="unrecoverable",
                        recommended_next_step=(
                            "File cannot be restored to its original location. "
                            "Manual recovery from quarantine path is possible."
                        ),
                    ))

                # Check for invalid record (missing required fields)
                if not rec.action_id:
                    invalid_record_count += 1
                    issues.append(ReconciliationIssue(
                        issue_type="invalid_record",
                        issue_id=_next_issue_id(),
                        quarantine_path=qpath,
                        record_id=rec.id,
                        detected_at=detected_at,
                        explanation=f"Record #{rec.id} is missing action_id.",
                        recoverability="requires_manual_review",
                        recommended_next_step="Manual review required to determine record validity.",
                    ))

    # Check for records pointing to missing files
    record_without_file_count = 0
    for rec in records:
        qpath = rec.quarantine_path
        if not qpath or not Path(qpath).exists():
            record_without_file_count += 1
            issues.append(ReconciliationIssue(
                issue_type="record_without_file",
                issue_id=_next_issue_id(),
                quarantine_path=qpath,
                record_id=rec.id,
                original_path=rec.original_path,
                size=rec.original_size,
                detected_at=detected_at,
                explanation=(
                    f"Record #{rec.id} references missing file: "
                    f"{qpath or '(empty path)'}. "
                    f"Original location: {rec.original_path or '(unknown)'}."
                ),
                recoverability="requires_manual_review",
                recommended_next_step=(
                    "Manual review required. File may have been restored "
                    "or deleted outside the system."
                ),
            ))

    # Build summary counts
    valid_record_count = scanned_files - file_without_record_count

    return ReconciliationReport(
        scanned_files=scanned_files,
        valid_records=valid_record_count,
        file_without_record_count=file_without_record_count,
        record_without_file_count=record_without_file_count,
        duplicate_record_count=duplicate_record_count,
        invalid_record_count=invalid_record_count,
        issues=issues,
        detected_at=detected_at,
    )


@dataclass(frozen=True)
class ReconciliationReport:
    """Structured reconciliation result.

    A clean reconciliation (clean=True) means "No detected inconsistency."
    """

    scanned_files: int = 0
    valid_records: int = 0
    file_without_record_count: int = 0
    record_without_file_count: int = 0
    duplicate_record_count: int = 0
    invalid_record_count: int = 0
    issues: tuple[ReconciliationIssue, ...] = ()
    detected_at: str = ""

    @property
    def clean(self) -> bool:
        """True if no inconsistencies were detected."""
        return len(self.issues) == 0

    @property
    def total_issues(self) -> int:
        """Total number of issues found."""
        return len(self.issues)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "scanned_files": self.scanned_files,
            "valid_records": self.valid_records,
            "file_without_record_count": self.file_without_record_count,
            "record_without_file_count": self.record_without_file_count,
            "duplicate_record_count": self.duplicate_record_count,
            "invalid_record_count": self.invalid_record_count,
            "total_issues": self.total_issues,
            "clean": self.clean,
            "detected_at": self.detected_at,
            "issues": [
                {
                    "issue_id": i.issue_id,
                    "issue_type": i.issue_type,
                    "quarantine_path": i.quarantine_path,
                    "record_id": i.record_id,
                    "original_path": i.original_path,
                    "size": i.size,
                    "detected_at": i.detected_at,
                    "explanation": i.explanation,
                    "recoverability": i.recoverability,
                    "recommended_next_step": i.recommended_next_step,
                }
                for i in self.issues
            ],
        }
