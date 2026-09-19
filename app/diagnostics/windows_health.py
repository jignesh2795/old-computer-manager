"""Read-only Windows health diagnostics.

Collects Windows version/build, reboot-required indicators, uptime,
and crash/reliability summary only through safe local sources.
Does NOT run repairs, trigger Windows Update, or change update settings.
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from app.diagnostics._powershell import run_powershell
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

_DIAG_ID = "windows_health"


def _collect_windows_version() -> dict[str, Any] | None:
    """Collect Windows version information."""
    if platform.system() != "Windows":
        return None

    script = (
        "$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue\n"
        "if ($os) {\n"
        "    $os | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime,SystemType |\n"
        "        ConvertTo-Json -Compress\n"
        "}"
    )
    raw, error = run_powershell(script)
    if error or raw is None:
        return None

    item = raw if isinstance(raw, dict) else (raw[0] if isinstance(raw, list) and raw else None)
    if not item:
        return None

    return {
        "caption": item.get("Caption", "Unknown"),
        "version": item.get("Version", "Unknown"),
        "build_number": item.get("BuildNumber", "Unknown"),
        "architecture": item.get("OSArchitecture", "Unknown"),
        "last_boot": item.get("LastBootUpTime", "Unknown"),
        "system_type": item.get("SystemType", "Unknown"),
    }


def _collect_reboot_required() -> dict[str, Any] | None:
    """Check if a reboot is required (read-only registry check)."""
    if platform.system() != "Windows":
        return None

    script = (
        "$reboot = $false\n"
        "try {\n"
        "    $pending = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' "
        "-Name 'RebootRequired' -ErrorAction SilentlyContinue\n"
        "    if ($pending) { $reboot = $true }\n"
        "} catch {}\n"
        "try {\n"
        "    $component = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing' "
        "-Name 'RebootPending' -ErrorAction SilentlyContinue\n"
        "    if ($component) { $reboot = $true }\n"
        "} catch {}\n"
        "ConvertTo-Json @{ reboot_required = $reboot } -Compress"
    )
    raw, error = run_powershell(script)
    if error or raw is None:
        return None

    item = raw if isinstance(raw, dict) else {}
    return {"reboot_required": bool(item.get("reboot_required", False))}


def _collect_uptime() -> dict[str, Any] | None:
    """Collect system uptime."""
    try:
        import psutil
        boot_time = psutil.boot_time()
        import time
        uptime_seconds = time.time() - boot_time
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return {
            "uptime_seconds": int(uptime_seconds),
            "days": days,
            "hours": hours,
            "minutes": minutes,
            "formatted": f"{days}d {hours}h {minutes}m",
        }
    except (AttributeError, RuntimeError, OSError):
        return None


def _collect_reliability() -> dict[str, Any] | None:
    """Collect reliability/history summary if available through safe WMI."""
    if platform.system() != "Windows":
        return None

    script = (
        "$recent = Get-CimInstance Win32_ReliabilityRecord -ErrorAction SilentlyContinue | "
        "Sort-Object -Property TimeGenerated -Descending | Select-Object -First 10\n"
        "if ($recent) {\n"
        "    $recent | Select-Object TimeGenerated,EventType,Source,Message |\n"
        "        ConvertTo-Json -Compress\n"
        "} else {\n"
        "    ConvertTo-Json @() -Compress\n"
        "}"
    )
    raw, error = run_powershell(script)
    if error or raw is None:
        return None

    items = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
    events = []
    for item in items[:10]:
        if isinstance(item, dict):
            events.append({
                "time": item.get("TimeGenerated", ""),
                "type": item.get("EventType", ""),
                "source": item.get("Source", ""),
                "message": (item.get("Message", "") or "")[:200],
            })

    return {"recent_events": events, "event_count": len(events)}


def collect_windows_health() -> list[DiagnosticResult]:
    """Collect Windows health information from safe local sources."""
    results: list[DiagnosticResult] = []

    if platform.system() != "Windows":
        results.append(DiagnosticResult(
            diagnostic_id=_DIAG_ID,
            category=DiagnosticCategory.WINDOWS,
            status=DiagnosticStatus.NOT_SUPPORTED,
            title="Windows health",
            summary="Windows health diagnostics are not supported on this platform.",
            source="platform_check",
        ))
        return results

    # Windows version
    version_info = _collect_windows_version()
    if version_info:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_version",
            category=DiagnosticCategory.WINDOWS,
            status=DiagnosticStatus.OK,
            title="Windows version",
            summary=f"{version_info['caption']} Build {version_info['build_number']}",
            evidence=version_info,
            source="Win32_OperatingSystem",
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_version",
            category=DiagnosticCategory.WINDOWS,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Windows version",
            summary="Windows version information could not be collected.",
            source="Win32_OperatingSystem",
        ))

    # Reboot required
    reboot = _collect_reboot_required()
    if reboot:
        reboot_needed = reboot.get("reboot_required", False)
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_reboot",
            category=DiagnosticCategory.WINDOWS,
            status=DiagnosticStatus.WARNING if reboot_needed else DiagnosticStatus.OK,
            title="Reboot required",
            summary="A system reboot is required." if reboot_needed else "No reboot required.",
            evidence=reboot,
            source="registry",
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_reboot",
            category=DiagnosticCategory.WINDOWS,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Reboot required",
            summary="Reboot-required status could not be determined.",
            source="registry",
        ))

    # Uptime
    uptime = _collect_uptime()
    if uptime:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_uptime",
            category=DiagnosticCategory.WINDOWS,
            status=DiagnosticStatus.OK,
            title="System uptime",
            summary=f"Uptime: {uptime['formatted']}",
            evidence=uptime,
            source="psutil",
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_uptime",
            category=DiagnosticCategory.WINDOWS,
            status=DiagnosticStatus.UNAVAILABLE,
            title="System uptime",
            summary="Uptime could not be determined.",
            source="psutil",
        ))

    # Reliability
    reliability = _collect_reliability()
    if reliability:
        event_count = reliability.get("event_count", 0)
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_reliability",
            category=DiagnosticCategory.WINDOWS,
            status=DiagnosticStatus.OK,
            title="Reliability history",
            summary=f"{event_count} recent reliability events found.",
            evidence=reliability,
            source="Win32_ReliabilityRecord",
            limitations=["Limited to last 10 events."],
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_reliability",
            category=DiagnosticCategory.WINDOWS,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Reliability history",
            summary="Reliability history is not available on this system.",
            source="Win32_ReliabilityRecord",
            limitations=["Win32_ReliabilityRecord may not be available on all Windows versions."],
        ))

    return results
