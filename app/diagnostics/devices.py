"""Read-only device/driver diagnostics.

Collects device name, class, status, problem code, manufacturer, and driver info.
Does NOT change devices or drivers. Does NOT install drivers.
Focuses on identifying devices explicitly reporting a problem.
"""

from __future__ import annotations

import platform
from typing import Any

from app.diagnostics._powershell import run_powershell
from app.diagnostics.constants import MAX_DEVICES_RETURNED
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

_DIAG_ID = "devices"

_WMI_QUERY = """
Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
    Select-Object Name,DeviceID,Status,ConfigManagerErrorCode,Manufacturer,DriverProviderName,DriverVersion,ClassGuid,PNPClass |
    ConvertTo-Json -Compress
"""


def _parse_device(raw: Any) -> dict[str, Any] | None:
    """Parse a single device WMI record."""
    if not isinstance(raw, dict):
        return None

    name = raw.get("Name", "Unknown Device")
    status = raw.get("Status", "Unknown")
    error_code = raw.get("ConfigManagerErrorCode")

    problem_code = None
    if error_code is not None:
        try:
            problem_code = int(error_code)
        except (ValueError, TypeError):
            pass

    return {
        "name": name,
        "device_id": raw.get("DeviceID", ""),
        "status": str(status),
        "problem_code": problem_code,
        "manufacturer": raw.get("Manufacturer", "Unknown"),
        "driver_provider": raw.get("DriverProviderName", "Unknown"),
        "driver_version": raw.get("DriverVersion", "Unknown"),
        "class_guid": raw.get("ClassGuid", ""),
        "pnp_class": raw.get("PNPClass", ""),
    }


def collect_devices() -> list[DiagnosticResult]:
    """Collect device information from Windows PnP."""
    results: list[DiagnosticResult] = []

    if platform.system() != "Windows":
        results.append(DiagnosticResult(
            diagnostic_id=_DIAG_ID,
            category=DiagnosticCategory.DEVICES,
            status=DiagnosticStatus.NOT_SUPPORTED,
            title="Device diagnostics",
            summary="Device diagnostics are not supported on this platform.",
            source="platform_check",
        ))
        return results

    raw, error = run_powershell(_WMI_QUERY)

    if error:
        results.append(DiagnosticResult(
            diagnostic_id=_DIAG_ID,
            category=DiagnosticCategory.DEVICES,
            status=DiagnosticStatus.FAILED,
            title="Device diagnostics",
            summary=f"Failed to query devices: {error}",
            source="Win32_PnPEntity",
            errors=[error],
        ))
        return results

    if raw is None:
        results.append(DiagnosticResult(
            diagnostic_id=_DIAG_ID,
            category=DiagnosticCategory.DEVICES,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Device diagnostics",
            summary="No device information was returned by Windows.",
            source="Win32_PnPEntity",
        ))
        return results

    items = raw if isinstance(raw, list) else [raw]
    all_devices: list[dict[str, Any]] = []
    problem_devices: list[dict[str, Any]] = []

    for item in items:
        parsed = _parse_device(item)
        if not parsed:
            continue
        all_devices.append(parsed)
        if parsed["problem_code"] is not None and parsed["problem_code"] != 0:
            problem_devices.append(parsed)

    # Summary result for all devices
    results.append(DiagnosticResult(
        diagnostic_id=f"{_DIAG_ID}_summary",
        category=DiagnosticCategory.DEVICES,
        status=DiagnosticStatus.OK if not problem_devices else DiagnosticStatus.WARNING,
        title="Device summary",
        summary=f"{len(all_devices)} devices detected, {len(problem_devices)} with problems",
        evidence={
            "total_count": len(all_devices),
            "problem_count": len(problem_devices),
        },
        source="Win32_PnPEntity",
        limitations=[f"Showing {min(len(items), MAX_DEVICES_RETURNED)} of {len(items)} devices." if len(items) > MAX_DEVICES_RETURNED else ""],
    ))

    # Individual problem devices
    for dev in problem_devices[:20]:
        code = dev["problem_code"]
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_problem_{dev['device_id'][:32]}",
            category=DiagnosticCategory.DEVICES,
            status=DiagnosticStatus.WARNING,
            title=f"Device problem: {dev['name']}",
            summary=f"Problem code {code}, Status: {dev['status']}",
            evidence=dev,
            source="Win32_PnPEntity",
        ))

    return results
