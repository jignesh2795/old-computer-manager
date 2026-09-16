"""Process analyzer -- detects high CPU and high memory processes."""

from __future__ import annotations

from typing import Any

from app.analyzers.constants import (
    PROCESS_HIGH_CPU_PERCENT,
    PROCESS_HIGH_MEMORY_FRACTION,
    PROCESS_TOP_N,
)
from app.analyzers.finding import Finding


name = "process"


def analyze(snapshots: dict[str, Any]) -> list[Finding]:
    """Analyze process snapshot for high CPU and high memory consumers.

    This is a point-in-time observation, not proof of a持续 problem.
    """
    processes = snapshots.get("processes")
    hardware = snapshots.get("hardware")

    if not processes or not isinstance(processes, list):
        return []

    total_ram = 0
    if hardware and isinstance(hardware, dict):
        total_ram = hardware.get("memory_total_bytes", 0) or 0

    findings: list[Finding] = []

    # -- High CPU --
    high_cpu = [
        p for p in processes
        if _safe_float(p.get("cpu_percent"), 0.0) >= PROCESS_HIGH_CPU_PERCENT
    ]
    high_cpu.sort(key=lambda p: _safe_float(p.get("cpu_percent"), 0.0), reverse=True)
    for proc in high_cpu[:PROCESS_TOP_N]:
        findings.append(
            Finding(
                analyzer=name,
                severity="warning",
                title=f"High CPU: {proc.get('name', 'unknown')} (PID {proc.get('pid', '?')})",
                message=(
                    f"Process '{proc.get('name', 'unknown')}' (PID {proc.get('pid', '?')}) "
                    f"is using {proc.get('cpu_percent', 0):.1f}% CPU. "
                    f"This is a snapshot observation, not proof of a持续 problem."
                ),
                evidence={
                    "pid": proc.get("pid"),
                    "name": proc.get("name"),
                    "username": proc.get("username"),
                    "cpu_percent": proc.get("cpu_percent"),
                },
                recommendation=(
                    "If this process consistently uses high CPU, investigate "
                    "whether it is expected behavior or a potential issue."
                ),
                metadata={"category": "high_cpu"},
            )
        )

    # -- High memory --
    if total_ram > 0:
        threshold_bytes = int(total_ram * PROCESS_HIGH_MEMORY_FRACTION)
        high_mem = [
            p for p in processes
            if _safe_int(p.get("memory_rss_bytes"), 0) >= threshold_bytes
        ]
        high_mem.sort(
            key=lambda p: _safe_int(p.get("memory_rss_bytes"), 0), reverse=True
        )
        for proc in high_mem[:PROCESS_TOP_N]:
            rss = _safe_int(proc.get("memory_rss_bytes"), 0)
            pct = (rss / total_ram) * 100
            findings.append(
                Finding(
                    analyzer=name,
                    severity="warning",
                    title=f"High memory: {proc.get('name', 'unknown')} (PID {proc.get('pid', '?')})",
                    message=(
                        f"Process '{proc.get('name', 'unknown')}' (PID {proc.get('pid', '?')}) "
                        f"is using {pct:.1f}% of physical RAM ({_format_bytes(rss)}). "
                        f"This is a snapshot observation, not proof of a持续 problem."
                    ),
                    evidence={
                        "pid": proc.get("pid"),
                        "name": proc.get("name"),
                        "username": proc.get("username"),
                        "memory_rss_bytes": rss,
                        "memory_percent": round(pct, 1),
                        "total_ram_bytes": total_ram,
                    },
                    recommendation=(
                        "If this process consistently uses high memory, investigate "
                        "whether it is expected behavior or a potential issue."
                    ),
                    metadata={"category": "high_memory"},
                )
            )

    return findings


def _safe_float(val: Any, default: float) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _safe_int(val: Any, default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} PB"
