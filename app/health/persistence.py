"""Health session persistence (Phase 12.6).

``HealthSessionStore`` owns orchestration persistence over the SQLite
database whose schema is managed by ``SnapshotStore``.  It constructs
``HealthSession``/``HealthStage`` domain objects; ``SnapshotStore``
never does.

Stored data are references (IDs, timestamps, configuration), never
evidence payloads: no snapshots, findings, diagnostics, or candidate
payloads are copied into the health tables.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from app.health.models import (
    DataQuality,
    HealthSession,
    HealthStage,
    HealthStageStatus,
    HealthStageType,
)


class HealthSessionStore:
    """SQLite-backed storage for health sessions and stages.

    The ``health_sessions``/``health_stages`` tables are created by
    ``SnapshotStore`` migration; this store only reads and writes rows.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    @contextmanager
    def _connect(self):  # type: ignore[no-untyped-def]
        """Open a connection with foreign-key enforcement enabled."""
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

    # -- writes ---------------------------------------------------------

    def create_session(self, session: HealthSession) -> None:
        """Insert a session row.  Raises on duplicate session_id."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO health_sessions("
                "  session_id, profile, status, created_at, started_at,"
                "  completed_at, budgets_json, data_quality,"
                "  discovery_run_id, evidence_ids_json, error"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session.session_id,
                    session.profile,
                    session.status.value,
                    session.created_at,
                    session.started_at,
                    session.completed_at,
                    json.dumps(session.budgets, sort_keys=True),
                    session.data_quality.value,
                    session.discovery_run_id,
                    json.dumps(list(session.evidence_ids), sort_keys=True),
                    None,
                ),
            )

    def save_stage(self, session_id: str, stage: HealthStage) -> None:
        """Insert or replace a stage row (one row per session+type)."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO health_stages("
                "  session_id, stage_id, stage_type, status, started_at,"
                "  completed_at, duration_ms, error, evidence_timestamp,"
                "  data_quality, discovery_run_id, evidence_ids_json,"
                "  provenance_json"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(session_id, stage_type) DO UPDATE SET"
                "  stage_id = excluded.stage_id,"
                "  status = excluded.status,"
                "  started_at = excluded.started_at,"
                "  completed_at = excluded.completed_at,"
                "  duration_ms = excluded.duration_ms,"
                "  error = excluded.error,"
                "  evidence_timestamp = excluded.evidence_timestamp,"
                "  data_quality = excluded.data_quality,"
                "  discovery_run_id = excluded.discovery_run_id,"
                "  evidence_ids_json = excluded.evidence_ids_json,"
                "  provenance_json = excluded.provenance_json",
                (
                    session_id,
                    stage.stage_id,
                    stage.stage_type.value,
                    stage.status.value,
                    stage.started_at,
                    stage.completed_at,
                    stage.duration_ms,
                    stage.error,
                    stage.evidence_timestamp,
                    stage.data_quality.value,
                    None,
                    json.dumps(list(stage.evidence_refs), sort_keys=True),
                    json.dumps(stage.provenance, sort_keys=True),
                ),
            )

    def finalize_session(self, session: HealthSession) -> None:
        """Write the final session state.  Raises if the row is missing."""
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE health_sessions SET"
                "  status = ?, started_at = ?, completed_at = ?,"
                "  budgets_json = ?, data_quality = ?,"
                "  discovery_run_id = ?, evidence_ids_json = ?"
                " WHERE session_id = ?",
                (
                    session.status.value,
                    session.started_at,
                    session.completed_at,
                    json.dumps(session.budgets, sort_keys=True),
                    session.data_quality.value,
                    session.discovery_run_id,
                    json.dumps(list(session.evidence_ids), sort_keys=True),
                    session.session_id,
                ),
            )
            if cursor.rowcount == 0:
                raise ValueError(
                    f"Cannot finalize unknown session: {session.session_id}"
                )

    # -- reads ----------------------------------------------------------

    def get_session(self, session_id: str) -> HealthSession | None:
        """Load a session with its stages, or None when unknown."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT session_id, profile, status, created_at, started_at,"
                "  completed_at, budgets_json, data_quality,"
                "  discovery_run_id, evidence_ids_json"
                " FROM health_sessions WHERE session_id = ?",
                (session_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
        stages = self.get_stages(session_id)
        return _row_to_session(row, stages)

    def get_stages(self, session_id: str) -> list[HealthStage]:
        """Load a session's stages in insertion order."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT stage_id, stage_type, status, started_at,"
                "  completed_at, duration_ms, error, evidence_timestamp,"
                "  data_quality, evidence_ids_json, provenance_json"
                " FROM health_stages WHERE session_id = ? ORDER BY id",
                (session_id,),
            )
            return [_row_to_stage(row) for row in cursor.fetchall()]

    def list_sessions(self, limit: int = 50) -> list[HealthSession]:
        """List recent sessions, newest first, with stages attached."""
        with self._connect() as connection:
            cursor = connection.execute(
                "SELECT session_id FROM health_sessions"
                " ORDER BY rowid DESC LIMIT ?",
                (limit,),
            )
            session_ids = [row[0] for row in cursor.fetchall()]
        return [
            session
            for session_id in session_ids
            if (session := self.get_session(session_id)) is not None
        ]


def _row_to_session(
    row: tuple, stages: list[HealthStage]
) -> HealthSession:
    """Rebuild the domain model; unknown enums raise ValueError."""
    return HealthSession(
        session_id=row[0],
        profile=row[1],
        created_at=row[3],
        started_at=row[4],
        completed_at=row[5],
        status=HealthStageStatus(row[2]),
        stages=tuple(stages),
        budgets=dict(json.loads(row[6] or "{}")),
        data_quality=DataQuality(row[7]),
        discovery_run_id=row[8],
        evidence_ids=tuple(json.loads(row[9] or "[]")),
    )


def _row_to_stage(row: tuple) -> HealthStage:
    """Rebuild the domain model; unknown enums raise ValueError."""
    refs: Any = json.loads(row[9] or "[]")
    provenance: Any = json.loads(row[10] or "{}")
    return HealthStage(
        stage_id=row[0],
        stage_type=HealthStageType(row[1]),
        status=HealthStageStatus(row[2]),
        started_at=row[3],
        completed_at=row[4],
        duration_ms=row[5],
        error=row[6],
        evidence_timestamp=row[7],
        data_quality=DataQuality(row[8]),
        provenance=dict(provenance),
        evidence_refs=tuple(refs),
    )
