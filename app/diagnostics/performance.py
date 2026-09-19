"""Read-only performance snapshot diagnostics.

Collects CPU, memory, disk I/O, and network I/O snapshots.
Does NOT run stress tests, benchmarks, or continuous polling.
Does NOT generate a subjective performance score.
"""

from __future__ import annotations

import time
from typing import Any

import psutil

from app.diagnostics.constants import (
    CPU_HIGH_PERCENT,
    DISK_IO_HIGH_READ_BYTES_PER_SEC,
    DISK_IO_HIGH_WRITE_BYTES_PER_SEC,
    MEMORY_HIGH_PERCENT,
)
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

_DIAG_ID = "performance"


def _collect_cpu() -> dict[str, Any]:
    """Collect CPU utilization snapshot."""
    try:
        overall = psutil.cpu_percent(interval=1)
        per_core = psutil.cpu_percent(interval=0, percpu=True)
        count_logical = psutil.cpu_count()
        count_physical = psutil.cpu_count(logical=False)
    except (AttributeError, RuntimeError, OSError):
        overall = None
        per_core = []
        count_logical = None
        count_physical = None

    return {
        "overall_percent": overall,
        "per_core_percent": per_core,
        "count_logical": count_logical,
        "count_physical": count_physical,
    }


def _collect_memory() -> dict[str, Any]:
    """Collect memory utilization snapshot.

    On some Windows machines, psutil.swap_memory() fails because
    performance counters are disabled. We report memory data from
    virtual_memory() regardless of swap status.
    """
    vm = None
    swap = None
    errors: list[str] = []

    try:
        vm = psutil.virtual_memory()
    except (AttributeError, RuntimeError, OSError) as exc:
        errors.append(f"virtual_memory failed: {exc}")

    try:
        swap = psutil.swap_memory()
    except (AttributeError, RuntimeError, OSError) as exc:
        errors.append(f"swap_memory unavailable: {exc}")

    if vm is None:
        return {"available": False, "errors": errors}

    return {
        "available": True,
        "total_bytes": vm.total,
        "available_bytes": vm.available,
        "used_bytes": vm.used,
        "percent": vm.percent,
        "swap_total_bytes": swap.total if swap else None,
        "swap_used_bytes": swap.used if swap else None,
        "swap_percent": swap.percent if swap else None,
        "errors": errors,
    }


def _collect_disk_io() -> dict[str, Any]:
    """Collect disk I/O counters snapshot.

    Samples twice with a short interval to compute I/O rate.
    Cumulative totals are reported as informational telemetry.
    Only the rate is used for warning classification.
    """
    try:
        counters1 = psutil.disk_io_counters()
    except (AttributeError, RuntimeError, OSError):
        return {"available": False}

    if counters1 is None:
        return {"available": False}

    read_bytes_1 = counters1.read_bytes
    write_bytes_1 = counters1.write_bytes
    read_count_1 = counters1.read_count
    write_count_1 = counters1.write_count

    time.sleep(1.0)

    try:
        counters2 = psutil.disk_io_counters()
    except (AttributeError, RuntimeError, OSError):
        # Fall back to cumulative-only if second sample fails
        return {
            "available": True,
            "cumulative_read_bytes": read_bytes_1,
            "cumulative_write_bytes": write_bytes_1,
            "cumulative_read_count": read_count_1,
            "cumulative_write_count": write_count_1,
            "read_bytes_per_sec": None,
            "write_bytes_per_sec": None,
            "read_count_per_sec": None,
            "write_count_per_sec": None,
            "interval_seconds": None,
        }

    if counters2 is None:
        return {
            "available": True,
            "cumulative_read_bytes": read_bytes_1,
            "cumulative_write_bytes": write_bytes_1,
            "cumulative_read_count": read_count_1,
            "cumulative_write_count": write_count_1,
            "read_bytes_per_sec": None,
            "write_bytes_per_sec": None,
            "read_count_per_sec": None,
            "write_count_per_sec": None,
            "interval_seconds": None,
        }

    interval = 1.0
    read_bps = (counters2.read_bytes - read_bytes_1) / interval
    write_bps = (counters2.write_bytes - write_bytes_1) / interval
    read_cps = (counters2.read_count - read_count_1) / interval
    write_cps = (counters2.write_count - write_count_1) / interval

    return {
        "available": True,
        "cumulative_read_bytes": counters2.read_bytes,
        "cumulative_write_bytes": counters2.write_bytes,
        "cumulative_read_count": counters2.read_count,
        "cumulative_write_count": counters2.write_count,
        "read_bytes_per_sec": read_bps,
        "write_bytes_per_sec": write_bps,
        "read_count_per_sec": read_cps,
        "write_count_per_sec": write_cps,
        "interval_seconds": interval,
    }


def _collect_network_io() -> dict[str, Any]:
    """Collect network I/O counters snapshot."""
    try:
        counters = psutil.net_io_counters()
        per_nic = psutil.net_io_counters(pernic=True)
    except (AttributeError, RuntimeError, OSError):
        return {"available": False}

    interfaces = {}
    if per_nic:
        for name, nic in per_nic.items():
            interfaces[name] = {
                "bytes_sent": nic.bytes_sent,
                "bytes_recv": nic.bytes_recv,
                "packets_sent": nic.packets_sent,
                "packets_recv": nic.packets_recv,
            }

    return {
        "available": True,
        "total_bytes_sent": counters.bytes_sent if counters else 0,
        "total_bytes_recv": counters.bytes_recv if counters else 0,
        "interfaces": interfaces,
    }


def collect_performance() -> list[DiagnosticResult]:
    """Collect a lightweight read-only performance snapshot."""
    results: list[DiagnosticResult] = []

    cpu = _collect_cpu()
    memory = _collect_memory()
    disk_io = _collect_disk_io()
    network = _collect_network_io()

    # ── CPU ──────────────────────────────────────────────────────────────
    cpu_percent = cpu.get("overall_percent")
    if cpu_percent is not None:
        cpu_status = DiagnosticStatus.WARNING if cpu_percent >= CPU_HIGH_PERCENT else DiagnosticStatus.OK
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_cpu",
            category=DiagnosticCategory.PERFORMANCE,
            status=cpu_status,
            title="CPU utilization",
            summary=f"Overall CPU utilization: {cpu_percent}%",
            evidence=cpu,
            source="psutil",
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_cpu",
            category=DiagnosticCategory.PERFORMANCE,
            status=DiagnosticStatus.UNAVAILABLE,
            title="CPU utilization",
            summary="CPU utilization could not be collected.",
            source="psutil",
        ))

    # ── Memory ───────────────────────────────────────────────────────────
    if memory.get("available"):
        mem_percent = memory["percent"]
        mem_status = DiagnosticStatus.WARNING if mem_percent >= MEMORY_HIGH_PERCENT else DiagnosticStatus.OK
        total_gb = memory["total_bytes"] / (1024 ** 3)
        avail_gb = memory["available_bytes"] / (1024 ** 3)
        limitations: list[str] = []
        if memory.get("errors"):
            limitations.extend(memory["errors"])
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_memory",
            category=DiagnosticCategory.PERFORMANCE,
            status=mem_status,
            title="Memory utilization",
            summary=f"Memory: {mem_percent}% used ({avail_gb:.1f} GB available of {total_gb:.1f} GB)",
            evidence=memory,
            source="psutil",
            limitations=limitations,
        ))
    else:
        errors = memory.get("errors", [])
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_memory",
            category=DiagnosticCategory.PERFORMANCE,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Memory utilization",
            summary="Memory information could not be collected.",
            source="psutil",
            errors=errors,
        ))

    # ── Disk I/O ─────────────────────────────────────────────────────────
    if disk_io.get("available"):
        cumulative_read_gb = disk_io["cumulative_read_bytes"] / (1024 ** 3)
        cumulative_write_gb = disk_io["cumulative_write_bytes"] / (1024 ** 3)
        read_bps = disk_io.get("read_bytes_per_sec")
        write_bps = disk_io.get("write_bytes_per_sec")
        interval = disk_io.get("interval_seconds")

        if read_bps is not None and write_bps is not None:
            read_mb = read_bps / (1024 ** 2)
            write_mb = write_bps / (1024 ** 2)
            high_io = (
                read_bps >= DISK_IO_HIGH_READ_BYTES_PER_SEC
                or write_bps >= DISK_IO_HIGH_WRITE_BYTES_PER_SEC
            )
            io_status = DiagnosticStatus.WARNING if high_io else DiagnosticStatus.OK
            summary = (
                f"Read: {read_mb:.1f} MB/s, Write: {write_mb:.1f} MB/s "
                f"(measured over {interval:.0f}s). "
                f"Cumulative: {cumulative_read_gb:.2f} GB read, {cumulative_write_gb:.2f} GB written since boot."
            )
        else:
            io_status = DiagnosticStatus.OK
            summary = (
                f"Cumulative: {cumulative_read_gb:.2f} GB read, "
                f"{cumulative_write_gb:.2f} GB written since boot. "
                f"Rate measurement unavailable."
            )

        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_disk_io",
            category=DiagnosticCategory.PERFORMANCE,
            status=io_status,
            title="Disk I/O",
            summary=summary,
            evidence=disk_io,
            source="psutil",
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_disk_io",
            category=DiagnosticCategory.PERFORMANCE,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Disk I/O",
            summary="Disk I/O counters could not be collected.",
            source="psutil",
        ))

    # ── Network I/O ──────────────────────────────────────────────────────
    if network.get("available"):
        sent_gb = network["total_bytes_sent"] / (1024 ** 3)
        recv_gb = network["total_bytes_recv"] / (1024 ** 3)
        nic_count = len(network.get("interfaces", {}))
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_network_io",
            category=DiagnosticCategory.PERFORMANCE,
            status=DiagnosticStatus.OK,
            title="Network I/O",
            summary=f"Cumulative: sent {sent_gb:.2f} GB, received {recv_gb:.2f} GB across {nic_count} interfaces since boot",
            evidence=network,
            source="psutil",
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_network_io",
            category=DiagnosticCategory.PERFORMANCE,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Network I/O",
            summary="Network I/O counters could not be collected.",
            source="psutil",
        ))

    return results
