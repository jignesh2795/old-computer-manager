"""Orchestrates the safe v0.1 discovery run."""

from __future__ import annotations

from app.collectors import hardware, storage, windows
from app.database.sqlite import SnapshotStore


def run(store: SnapshotStore | None = None) -> dict[str, object]:
    store = store or SnapshotStore()

    results: dict[str, object] = {
        "hardware": hardware.collect_dict(),
        "storage": storage.collect(),
        "windows_os": windows.collect_os(),
        "windows_bios": windows.collect_bios(),
        "windows_computer_system": windows.collect_computer_system(),
    }

    for category, payload in results.items():
        store.save(category, payload)

    return results
