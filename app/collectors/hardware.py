"""Cross-platform, read-only hardware discovery using psutil/platform."""

from __future__ import annotations

import platform
import psutil
from dataclasses import asdict, dataclass

from app.collectors.result import CollectorResult


@dataclass(frozen=True)
class HardwareSnapshot:
    hostname: str
    system: str
    release: str
    machine: str
    processor: str
    cpu_physical_cores: int | None
    cpu_logical_cores: int | None
    memory_total_bytes: int


def collect() -> HardwareSnapshot:
    return HardwareSnapshot(
        hostname=platform.node(),
        system=platform.system(),
        release=platform.release(),
        machine=platform.machine(),
        processor=platform.processor(),
        cpu_physical_cores=psutil.cpu_count(logical=False),
        cpu_logical_cores=psutil.cpu_count(logical=True),
        memory_total_bytes=psutil.virtual_memory().total,
    )


def collect_result() -> CollectorResult:
    """Return a JSON/SQLite-friendly representation of the snapshot."""
    return CollectorResult(payload=asdict(collect()), status="ok")
