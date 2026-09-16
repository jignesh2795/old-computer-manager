"""Storage analyzer -- detects high disk usage."""

from __future__ import annotations

from typing import Any

from app.analyzers.constants import STORAGE_CRITICAL_THRESHOLD, STORAGE_WARNING_THRESHOLD
from app.analyzers.finding import Finding


name = "storage"


def analyze(snapshots: dict[str, Any]) -> list[Finding]:
    """Analyze storage snapshot for partitions with high usage.

    Thresholds:
        >= 80% used -> warning
        >= 90% used -> critical
    """
    payload = snapshots.get("storage")
    if not payload or not isinstance(payload, list):
        return []

    findings: list[Finding] = []

    for partition in payload:
        percent = partition.get("percent_used")
        if percent is None:
            continue

        device = partition.get("device", "unknown")
        mountpoint = partition.get("mountpoint", "unknown")
        filesystem = partition.get("filesystem", "unknown")
        total = partition.get("total_bytes")
        free = partition.get("free_bytes")

        evidence = {
            "device": device,
            "mountpoint": mountpoint,
            "filesystem": filesystem,
            "percent_used": percent,
            "total_bytes": total,
            "free_bytes": free,
        }

        if percent >= STORAGE_CRITICAL_THRESHOLD:
            findings.append(
                Finding(
                    analyzer=name,
                    severity="critical",
                    title=f"Disk usage critical on {mountpoint}",
                    message=(
                        f"{mountpoint} ({device}, {filesystem}) is {percent:.1f}% full. "
                        f"Free space: {_format_bytes(free)} of {_format_bytes(total)}."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Consider removing unnecessary files or moving data to "
                        "free up disk space on this partition."
                    ),
                )
            )
        elif percent >= STORAGE_WARNING_THRESHOLD:
            findings.append(
                Finding(
                    analyzer=name,
                    severity="warning",
                    title=f"Disk usage high on {mountpoint}",
                    message=(
                        f"{mountpoint} ({device}, {filesystem}) is {percent:.1f}% full. "
                        f"Free space: {_format_bytes(free)} of {_format_bytes(total)}."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Monitor disk usage on this partition. If usage continues "
                        "to grow, consider freeing up space."
                    ),
                )
            )

    return findings


def _format_bytes(n: int | float | None) -> str:
    """Format a byte count into a human-readable string."""
    if n is None:
        return "unknown"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} PB"
