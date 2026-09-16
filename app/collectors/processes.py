"""Low-overhead read-only process snapshot."""

from __future__ import annotations

import psutil

from app.collectors.result import CollectorResult


def collect_result() -> CollectorResult:
    results: list[dict[str, object]] = []
    for process in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info", "create_time"]):
        try:
            info = process.info
            memory = info.get("memory_info")
            results.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "username": info.get("username"),
                    "cpu_percent": info.get("cpu_percent"),
                    "memory_rss_bytes": getattr(memory, "rss", None),
                    "create_time": info.get("create_time"),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    results.sort(key=lambda item: item.get("memory_rss_bytes") or 0, reverse=True)
    status = "ok" if results else "empty"
    return CollectorResult(payload=results, status=status)
