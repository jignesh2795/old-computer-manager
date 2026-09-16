"""Read-only storage discovery."""

from __future__ import annotations

import psutil

from app.collectors.result import CollectorResult


def collect_result() -> CollectorResult:
    """Collect mounted filesystem information without modifying anything."""
    results: list[dict[str, object]] = []
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            results.append(
                {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "filesystem": partition.fstype,
                    "options": partition.opts,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent_used": usage.percent,
                }
            )
        except (PermissionError, FileNotFoundError, OSError):
            # A disappearing/unreadable mount must not abort the discovery run.
            results.append(
                {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "filesystem": partition.fstype,
                    "options": partition.opts,
                    "total_bytes": None,
                    "used_bytes": None,
                    "free_bytes": None,
                    "percent_used": None,
                }
            )
    status = "ok" if results else "empty"
    return CollectorResult(payload=results, status=status)
