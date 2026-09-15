"""Minimal local SQLite store for discovery snapshots."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    category TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_category_time
ON snapshots(category, collected_at);
"""


class SnapshotStore:
    def __init__(self, path: str | Path = "data/computer.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.executescript(SCHEMA)

    def save(self, category: str, payload: Any) -> int:
        with sqlite3.connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT INTO snapshots(category, payload_json) VALUES (?, ?)",
                (category, json.dumps(payload, default=str, sort_keys=True)),
            )
            return int(cursor.lastrowid)
