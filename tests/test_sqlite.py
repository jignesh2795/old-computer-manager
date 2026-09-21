"""Tests for the SQLite store."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from app.database.sqlite import SnapshotStore


class TestForeignKeyEnforcement:
    def test_foreign_keys_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SnapshotStore(path=db_path)

            with store._connect() as conn:
                row = conn.execute("PRAGMA foreign_keys").fetchone()
                assert row is not None
                assert row[0] == 1

    def test_insert_with_invalid_run_id_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SnapshotStore(path=db_path)

            try:
                store.save(
                    "test",
                    {"x": 1},
                    run_id=9999,
                    status="ok",
                )
                raised = False
            except sqlite3.IntegrityError:
                raised = True

            assert raised, "Expected IntegrityError for invalid run_id"

    def test_insert_with_valid_run_id_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SnapshotStore(path=db_path)

            run_id = store.start_run()
            row_id = store.save("test", {"x": 1}, run_id=run_id, status="ok")
            assert row_id > 0

    def test_insert_with_null_run_id_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SnapshotStore(path=db_path)

            row_id = store.save("test", {"x": 1}, run_id=None, status="ok")
            assert row_id > 0


class TestMigration:
    def test_migrate_old_schema_preserves_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            conn = sqlite3.connect(db_path)
            conn.executescript(
                "CREATE TABLE snapshots ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "    category TEXT NOT NULL,"
                "    payload_json TEXT NOT NULL"
                ");"
                "INSERT INTO snapshots(category, payload_json)"
                " VALUES ('hardware', '{\"ram\": 8}');"
            )
            conn.close()

            store = SnapshotStore(path=db_path)

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("PRAGMA table_info(snapshots)")
            columns = {row[1] for row in c.fetchall()}
            conn.close()

            assert "run_id" in columns
            assert "status" in columns
            assert "error_message" in columns

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("SELECT category, payload_json, status FROM snapshots")
            row = c.fetchone()
            conn.close()

            assert row[0] == "hardware"
            assert row[1] == '{"ram": 8}'
            assert row[2] == "ok"

    def test_migrate_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            store1 = SnapshotStore(path=db_path)
            run_id = store1.start_run()
            store1.save("test", {"x": 1}, run_id=run_id)

            store2 = SnapshotStore(path=db_path)

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("SELECT count(*) FROM snapshots")
            count = c.fetchone()[0]
            conn.close()

            assert count == 1


class TestHealthTablesMigration:
    def test_fresh_database_creates_health_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            SnapshotStore(path=db_path)

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
                " AND name IN ('health_sessions', 'health_stages')"
            )
            tables = {row[0] for row in c.fetchall()}
            conn.close()

            assert tables == {"health_sessions", "health_stages"}

    def test_existing_database_gains_tables_preserves_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            conn = sqlite3.connect(db_path)
            conn.executescript(
                "CREATE TABLE discovery_runs ("
                "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "    started_at TEXT,"
                "    completed_at TEXT,"
                "    status TEXT"
                ");"
                "INSERT INTO discovery_runs(status) VALUES ('completed');"
            )
            conn.close()

            SnapshotStore(path=db_path)

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
                " AND name IN ('health_sessions', 'health_stages')"
            )
            tables = {row[0] for row in c.fetchall()}
            c.execute("SELECT status FROM discovery_runs")
            old_row = c.fetchone()
            conn.close()

            assert tables == {"health_sessions", "health_stages"}
            assert old_row[0] == "completed"

    def test_health_migration_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            SnapshotStore(path=db_path)
            SnapshotStore(path=db_path)

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table'"
                " AND name IN ('health_sessions', 'health_stages')"
            )
            count = c.fetchone()[0]
            conn.close()

            assert count == 2


class TestRunLifecycle:
    def test_start_and_complete_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = SnapshotStore(path=db_path)

            run_id = store.start_run()
            assert run_id > 0

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("SELECT status, started_at FROM discovery_runs WHERE id = ?", (run_id,))
            row = c.fetchone()
            conn.close()

            assert row[0] == "running"
            assert row[1] is not None

            store.complete_run(run_id, status="completed")

            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute(
                "SELECT status, completed_at FROM discovery_runs WHERE id = ?", (run_id,)
            )
            row = c.fetchone()
            conn.close()

            assert row[0] == "completed"
            assert row[1] is not None
