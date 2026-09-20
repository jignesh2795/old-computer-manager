"""Read-only boot/startup timing diagnostics.

Collects boot duration, last boot time, and startup program count.
Does NOT modify startup entries, services, or boot configuration.
"""

from __future__ import annotations

import platform
import time
from typing import Any

import psutil

from app.diagnostics._powershell import run_powershell
from app.diagnostics.constants import BOOT_SLOW_SECONDS
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

_DIAG_ID = "boot_timing"


def _collect_boot_time() -> dict[str, Any] | None:
    """Collect last boot time and uptime for boot analysis."""
    try:
        boot_timestamp = psutil.boot_time()
        now = time.time()
        uptime_seconds = now - boot_timestamp
        from datetime import datetime, timezone
        boot_dt = datetime.fromtimestamp(boot_timestamp, tz=timezone.utc)
        return {
            "boot_timestamp": boot_timestamp,
            "boot_time_utc": boot_dt.isoformat(),
            "uptime_seconds": int(uptime_seconds),
        }
    except (AttributeError, RuntimeError, OSError):
        return None


def _collect_startup_programs() -> dict[str, Any] | None:
    """Count startup programs from registry (read-only).

    Checks both per-user and machine-wide startup locations.
    """
    if platform.system() != "Windows":
        return None

    script = (
        "$userStartup = Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-ErrorAction SilentlyContinue\n"
        "$machineStartup = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' "
        "-ErrorAction SilentlyContinue\n"
        "$userCount = 0\n"
        "$machineCount = 0\n"
        "if ($userStartup) {\n"
        "    $userCount = ($userStartup.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }).Count\n"
        "}\n"
        "if ($machineStartup) {\n"
        "    $machineCount = ($machineStartup.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }).Count\n"
        "}\n"
        "ConvertTo-Json @{ user_count = $userCount; machine_count = $machineCount; "
        "total = $userCount + $machineCount } -Compress"
    )
    raw, error = run_powershell(script)
    if error or raw is None:
        return None

    item = raw if isinstance(raw, dict) else {}
    return {
        "user_count": item.get("user_count", 0),
        "machine_count": item.get("machine_count", 0),
        "total": item.get("total", 0),
    }


def collect_boot_timing() -> list[DiagnosticResult]:
    """Collect boot/startup timing diagnostics."""
    results: list[DiagnosticResult] = []

    if platform.system() != "Windows":
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_boot_time",
            category=DiagnosticCategory.BOOT_TIMING,
            status=DiagnosticStatus.NOT_SUPPORTED,
            title="Boot timing",
            summary="Boot timing diagnostics are not supported on this platform.",
            source="platform_check",
        ))
        return results

    # Boot time and uptime
    boot_time = _collect_boot_time()
    if boot_time:
        uptime = boot_time["uptime_seconds"]
        days = uptime // 86400
        hours = (uptime % 86400) // 3600
        minutes = (uptime % 3600) // 60
        formatted = f"{days}d {hours}h {minutes}m"

        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_boot_time",
            category=DiagnosticCategory.BOOT_TIMING,
            status=DiagnosticStatus.OK,
            title="Last boot time",
            summary=f"System last booted {boot_time['boot_time_utc']}. Current uptime: {formatted}",
            evidence=boot_time,
            source="psutil",
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_boot_time",
            category=DiagnosticCategory.BOOT_TIMING,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Last boot time",
            summary="Boot time information could not be collected.",
            source="psutil",
        ))

    # Startup programs
    startup = _collect_startup_programs()
    if startup:
        total = startup.get("total", 0)
        user_count = startup.get("user_count", 0)
        machine_count = startup.get("machine_count", 0)

        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_startup_programs",
            category=DiagnosticCategory.BOOT_TIMING,
            status=DiagnosticStatus.OK,
            title="Startup programs",
            summary=f"{total} startup program(s): {user_count} user, {machine_count} machine",
            evidence=startup,
            source="registry",
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_startup_programs",
            category=DiagnosticCategory.BOOT_TIMING,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Startup programs",
            summary="Startup program count could not be collected.",
            source="registry",
        ))

    return results
