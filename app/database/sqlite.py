"""Minimal local SQLite store for discovery snapshots and analysis findings."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any


TABLES = """
CREATE TABLE IF NOT EXISTS discovery_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    analysis_status TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    category TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ok',
    error_message TEXT,
    FOREIGN KEY (run_id) REFERENCES discovery_runs(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    analyzer TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    evidence_json TEXT,
    recommendation TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES discovery_runs(id)
);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS idx_snapshots_category_time
ON snapshots(category, collected_at);
CREATE INDEX IF NOT EXISTS idx_snapshots_run_id
ON snapshots(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run_id
ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity
ON findings(severity);
"""


class SnapshotStore:
    def __init__(self, path: str | Path = "data/computer.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self):
        """Open a connection with foreign-key enforcement enabled."""
        connection = sqlite3.connect(self.path)
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
            self._migrate(connection)
            connection.executescript(TABLES)
            connection.executescript(INDEXES)

    def _migrate(self, connection: sqlite3.Connection) -> None:
        """Add columns/tables to existing databases."""
        # Migrate snapshots table (pre-run_id databases)
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='snapshots'"
        )
        if cursor.fetchone() is not None:
            cursor = connection.execute("PRAGMA table_info(snapshots)")
            existing = {row[1] for row in cursor.fetchall()}
            if "run_id" not in existing:
                connection.execute("ALTER TABLE snapshots ADD COLUMN run_id INTEGER")
            if "status" not in existing:
                connection.execute(
                    "ALTER TABLE snapshots ADD COLUMN status TEXT NOT NULL DEFAULT 'ok'"
                )
            if "error_message" not in existing:
                connection.execute(
                    "ALTER TABLE snapshots ADD COLUMN error_message TEXT"
                )

        # Create findings table if it does not exist (handles fresh DBs too)
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='findings'"
        )
        if cursor.fetchone() is None:
            connection.execute(
                "CREATE TABLE findings ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    run_id INTEGER NOT NULL,"
                "    analyzer TEXT NOT NULL,"
                "    severity TEXT NOT NULL,"
                "    title TEXT NOT NULL,"
                "    message TEXT NOT NULL,"
                "    evidence_json TEXT,"
                "    recommendation TEXT,"
                "    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "    FOREIGN KEY (run_id) REFERENCES discovery_runs(id)"
                ")"
            )

        # Migrate discovery_runs table: add analysis_status column
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='discovery_runs'"
        )
        if cursor.fetchone() is not None:
            cursor = connection.execute("PRAGMA table_info(discovery_runs)")
            existing_cols = {row[1] for row in cursor.fetchall()}
            if "analysis_status" not in existing_cols:
                connection.execute(
                    "ALTER TABLE discovery_runs "
                    "ADD COLUMN analysis_status TEXT"
                )

        # Create remediation_audit table if it does not exist
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='remediation_audit'"
        )
        if cursor.fetchone() is None:
            connection.execute(
                "CREATE TABLE remediation_audit ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    action_id TEXT NOT NULL,"
                "    finding_id INTEGER,"
                "    discovery_run_id INTEGER,"
                "    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "    executed_at TEXT,"
                "    status TEXT NOT NULL DEFAULT 'proposed',"
                "    risk_level TEXT NOT NULL DEFAULT 'low',"
                "    target TEXT NOT NULL DEFAULT '',"
                "    reason TEXT NOT NULL DEFAULT '',"
                "    result_summary TEXT NOT NULL DEFAULT '',"
                "    rollback_available INTEGER NOT NULL DEFAULT 0,"
                "    error_message TEXT"
                ")"
            )

        # Create quarantine_records table if it does not exist
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
                "    error_message TEXT,"
                "    FOREIGN KEY (audit_record_id) REFERENCES remediation_audit(id)"
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

        # Create file_scan_runs table if it does not exist
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='file_scan_runs'"
        )
        if cursor.fetchone() is None:
            connection.execute(
                "CREATE TABLE file_scan_runs ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    scan_root TEXT NOT NULL,"
                "    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "    completed_at TEXT,"
                "    status TEXT NOT NULL DEFAULT 'running',"
                "    stats_json TEXT"
                ")"
            )

        # Create file_scan_large_files table if it does not exist
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='file_scan_large_files'"
        )
        if cursor.fetchone() is None:
            connection.execute(
                "CREATE TABLE file_scan_large_files ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    scan_run_id INTEGER NOT NULL,"
                "    path TEXT NOT NULL,"
                "    size_bytes INTEGER NOT NULL,"
                "    FOREIGN KEY (scan_run_id) REFERENCES file_scan_runs(id)"
                ")"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_large_files_scan_run "
                "ON file_scan_large_files(scan_run_id)"
            )

        # Create file_scan_type_groups table if it does not exist
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='file_scan_type_groups'"
        )
        if cursor.fetchone() is None:
            connection.execute(
                "CREATE TABLE file_scan_type_groups ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    scan_run_id INTEGER NOT NULL,"
                "    extension TEXT NOT NULL,"
                "    file_count INTEGER NOT NULL,"
                "    total_size_bytes INTEGER NOT NULL,"
                "    FOREIGN KEY (scan_run_id) REFERENCES file_scan_runs(id)"
                ")"
            )

        # Create file_scan_duplicate_groups table if it does not exist
        cursor = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='file_scan_duplicate_groups'"
        )
        if cursor.fetchone() is None:
            connection.execute(
                "CREATE TABLE file_scan_duplicate_groups ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    scan_run_id INTEGER NOT NULL,"
                "    group_id INTEGER NOT NULL,"
                "    size_bytes INTEGER NOT NULL,"
                "    match_type TEXT NOT NULL,"
                "    hash_value TEXT,"
                "    paths_json TEXT NOT NULL,"
                "    FOREIGN KEY (scan_run_id) REFERENCES file_scan_runs(id)"
                ")"
            )

    def start_run(self) -> int:
        """Record the start of a discovery run. Returns the run id."""
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO discovery_runs(started_at, status) "
                "VALUES (datetime('now'), 'running')"
            )
            return int(cursor.lastrowid)

    def complete_run(self, run_id: int, status: str = "completed") -> None:
        """Mark a discovery run as completed or failed."""
        with self._connect() as connection:
            connection.execute(
                "UPDATE discovery_runs "
                "SET completed_at = datetime('now'), status = ? "
                "WHERE id = ?",
                (status, run_id),
            )

    def set_analysis_status(self, run_id: int, analysis_status: str) -> None:
        """Set the analysis_status for a discovery run.

        Valid values: 'not_run', 'completed', 'failed', 'partial'.
        """
        with self._connect() as connection:
            connection.execute(
                "UPDATE discovery_runs SET analysis_status = ? WHERE id = ?",
                (analysis_status, run_id),
            )

    def save(
        self,
        category: str,
        payload: Any,
        *,
        run_id: int | None = None,
        status: str = "ok",
        error_message: str | None = None,
    ) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO snapshots(run_id, category, payload_json, status, error_message) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    run_id,
                    category,
                    json.dumps(payload, default=str, sort_keys=True),
                    status,
                    error_message,
                ),
            )
            return int(cursor.lastrowid)

    def get_latest_completed_run(self) -> dict[str, Any] | None:
        """Return the most recent completed discovery run, or None."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT id, started_at, completed_at, status, analysis_status "
                "FROM discovery_runs "
                "WHERE status IN ('completed', 'completed_with_errors') "
                "ORDER BY id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return {
                "id": row[0],
                "started_at": row[1],
                "completed_at": row[2],
                "status": row[3],
                "analysis_status": row[4],
            }

    def load_snapshots(self, run_id: int) -> dict[str, Any]:
        """Load all snapshot payloads for a run, keyed by category.

        Only snapshots with status='ok' are loaded; failed/empty/not_supported
        snapshots are skipped so analyzers see only valid data.
        """
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT category, payload_json FROM snapshots "
                "WHERE run_id = ? AND status = 'ok'",
                (run_id,),
            )
            return {row[0]: json.loads(row[1]) for row in cursor.fetchall()}

    def load_findings(self, run_id: int) -> list[dict[str, Any]]:
        """Load all findings for a run."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT analyzer, severity, title, message, evidence_json, "
                "       recommendation, created_at "
                "FROM findings WHERE run_id = ? ORDER BY id",
                (run_id,),
            )
            return [
                {
                    "analyzer": row[0],
                    "severity": row[1],
                    "title": row[2],
                    "message": row[3],
                    "evidence": json.loads(row[4]) if row[4] else None,
                    "recommendation": row[5],
                    "created_at": row[6],
                }
                for row in cursor.fetchall()
            ]

    # -- File scan methods --------------------------------------------------

    def start_file_scan(self, scan_root: str) -> int:
        """Record the start of a file scan. Returns the scan run id."""
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO file_scan_runs(scan_root, status) "
                "VALUES (?, 'running')",
                (scan_root,),
            )
            return int(cursor.lastrowid)

    def complete_file_scan(
        self, scan_run_id: int, stats: dict[str, Any], status: str = "completed"
    ) -> None:
        """Mark a file scan as completed with stats."""
        with self._connect() as connection:
            connection.execute(
                "UPDATE file_scan_runs "
                "SET completed_at = datetime('now'), status = ?, stats_json = ? "
                "WHERE id = ?",
                (status, json.dumps(stats, default=str), scan_run_id),
            )

    def save_file_scan_large_files(
        self, scan_run_id: int, large_files: list[dict[str, Any]]
    ) -> None:
        """Persist large-file results."""
        with self._connect() as connection:
            for item in large_files:
                connection.execute(
                    "INSERT INTO file_scan_large_files(scan_run_id, path, size_bytes) "
                    "VALUES (?, ?, ?)",
                    (scan_run_id, item["path"], item["size_bytes"]),
                )

    def save_file_scan_type_groups(
        self, scan_run_id: int, type_groups: list[dict[str, Any]]
    ) -> None:
        """Persist file-type grouping results."""
        with self._connect() as connection:
            for item in type_groups:
                connection.execute(
                    "INSERT INTO file_scan_type_groups("
                    "  scan_run_id, extension, file_count, total_size_bytes"
                    ") VALUES (?, ?, ?, ?)",
                    (
                        scan_run_id,
                        item["extension"],
                        item["file_count"],
                        item["total_size_bytes"],
                    ),
                )

    def save_file_scan_duplicate_groups(
        self, scan_run_id: int, dup_groups: list[dict[str, Any]]
    ) -> None:
        """Persist duplicate group results."""
        with self._connect() as connection:
            for item in dup_groups:
                connection.execute(
                    "INSERT INTO file_scan_duplicate_groups("
                    "  scan_run_id, group_id, size_bytes, match_type, "
                    "  hash_value, paths_json"
                    ") VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        scan_run_id,
                        item["group_id"],
                        item["size_bytes"],
                        item["match_type"],
                        item.get("hash_value"),
                        json.dumps(item["paths"]),
                    ),
                )

    def get_latest_file_scan(self) -> dict[str, Any] | None:
        """Return the most recent completed file scan, or None."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT id, scan_root, started_at, completed_at, status, stats_json "
                "FROM file_scan_runs "
                "WHERE status = 'completed' "
                "ORDER BY id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return {
                "id": row[0],
                "scan_root": row[1],
                "started_at": row[2],
                "completed_at": row[3],
                "status": row[4],
                "stats": json.loads(row[5]) if row[5] else None,
            }

    def load_file_scan_large_files(self, scan_run_id: int) -> list[dict[str, Any]]:
        """Load large-file results for a scan run."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT path, size_bytes FROM file_scan_large_files "
                "WHERE scan_run_id = ? ORDER BY size_bytes DESC",
                (scan_run_id,),
            )
            return [{"path": row[0], "size_bytes": row[1]} for row in cursor.fetchall()]

    def load_file_scan_type_groups(self, scan_run_id: int) -> list[dict[str, Any]]:
        """Load file-type grouping results for a scan run."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT extension, file_count, total_size_bytes "
                "FROM file_scan_type_groups "
                "WHERE scan_run_id = ? ORDER BY total_size_bytes DESC",
                (scan_run_id,),
            )
            return [
                {
                    "extension": row[0],
                    "file_count": row[1],
                    "total_size_bytes": row[2],
                }
                for row in cursor.fetchall()
            ]

    def load_file_scan_duplicate_groups(
        self, scan_run_id: int
    ) -> list[dict[str, Any]]:
        """Load duplicate group results for a scan run."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT group_id, size_bytes, match_type, hash_value, paths_json "
                "FROM file_scan_duplicate_groups "
                "WHERE scan_run_id = ? ORDER BY group_id",
                (scan_run_id,),
            )
            return [
                {
                    "group_id": row[0],
                    "size_bytes": row[1],
                    "match_type": row[2],
                    "hash_value": row[3],
                    "paths": json.loads(row[4]),
                }
                for row in cursor.fetchall()
            ]

    # -- Historical query methods --------------------------------------------

    def get_completed_runs(
        self, limit: int | None = None, since_id: int | None = None
    ) -> list[dict[str, Any]]:
        """Return completed discovery runs, newest first.

        Args:
            limit: Maximum number of runs to return. None means all.
            since_id: Only return runs with id > since_id.

        Returns:
            List of run dicts with keys: id, started_at, completed_at, status, analysis_status.
        """
        with self._connect() as connection:
            query = (
                "SELECT id, started_at, completed_at, status, analysis_status "
                "FROM discovery_runs "
                "WHERE status IN ('completed', 'completed_with_errors')"
            )
            params: list[Any] = []
            if since_id is not None:
                query += " AND id > ?"
                params.append(since_id)
            query += " ORDER BY id DESC"
            if limit is not None:
                query += " LIMIT ?"
                params.append(limit)
            cursor = connection.execute(query, params)
            return [
                {
                    "id": row[0],
                    "started_at": row[1],
                    "completed_at": row[2],
                    "status": row[3],
                    "analysis_status": row[4],
                }
                for row in cursor.fetchall()
            ]

    def get_all_runs(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Return all discovery runs (any status), newest first."""
        with self._connect() as connection:
            query = (
                "SELECT id, started_at, completed_at, status, analysis_status "
                "FROM discovery_runs ORDER BY id DESC"
            )
            params: list[Any] = []
            if limit is not None:
                query += " LIMIT ?"
                params.append(limit)
            cursor = connection.execute(query, params)
            return [
                {
                    "id": row[0],
                    "started_at": row[1],
                    "completed_at": row[2],
                    "status": row[3],
                    "analysis_status": row[4],
                }
                for row in cursor.fetchall()
            ]

    def get_snapshots_for_runs(
        self, run_ids: list[int], category: str
    ) -> list[dict[str, Any]]:
        """Return snapshots for multiple runs, ordered by collected_at.

        Only returns snapshots with status='ok'.

        Args:
            run_ids: List of run IDs to query.
            category: Snapshot category (e.g. 'storage', 'battery').

        Returns:
            List of dicts with keys: run_id, collected_at, payload.
        """
        if not run_ids:
            return []
        placeholders = ",".join("?" for _ in run_ids)
        with self._connect() as connection:
            cursor = connection.execute(
                f"SELECT run_id, collected_at, payload_json "
                f"FROM snapshots "
                f"WHERE run_id IN ({placeholders}) "
                f"AND category = ? AND status = 'ok' "
                f"ORDER BY collected_at",
                [*run_ids, category],
            )
            return [
                {
                    "run_id": row[0],
                    "collected_at": row[1],
                    "payload": json.loads(row[2]),
                }
                for row in cursor.fetchall()
            ]

    def get_findings_for_runs(
        self, run_ids: list[int]
    ) -> list[dict[str, Any]]:
        """Return findings for multiple runs, ordered by created_at.

        Args:
            run_ids: List of run IDs to query.

        Returns:
            List of finding dicts.
        """
        if not run_ids:
            return []
        placeholders = ",".join("?" for _ in run_ids)
        with self._connect() as connection:
            cursor = connection.execute(
                f"SELECT run_id, analyzer, severity, title, message, "
                f"       evidence_json, recommendation, created_at "
                f"FROM findings "
                f"WHERE run_id IN ({placeholders}) "
                f"ORDER BY created_at",
                run_ids,
            )
            return [
                {
                    "run_id": row[0],
                    "analyzer": row[1],
                    "severity": row[2],
                    "title": row[3],
                    "message": row[4],
                    "evidence": json.loads(row[5]) if row[5] else None,
                    "recommendation": row[6],
                    "created_at": row[7],
                }
                for row in cursor.fetchall()
            ]

    def count_snapshots_by_category(
        self, run_ids: list[int]
    ) -> dict[str, int]:
        """Count snapshots per category across multiple runs.

        Returns:
            Dict mapping category name to total count.
        """
        if not run_ids:
            return {}
        placeholders = ",".join("?" for _ in run_ids)
        with self._connect() as connection:
            cursor = connection.execute(
                f"SELECT category, COUNT(*) FROM snapshots "
                f"WHERE run_id IN ({placeholders}) AND status = 'ok' "
                f"GROUP BY category",
                run_ids,
            )
            return {row[0]: row[1] for row in cursor.fetchall()}
