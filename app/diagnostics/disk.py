"""Read-only disk health diagnostics.

Collects physical disk model, interface, capacity, operational status,
health status, predictive failure, temperature, and SMART availability.

Does NOT run chkdsk, repair, defrag, or vendor utilities.
Does NOT store actual serial numbers.
"""

from __future__ import annotations

import platform
from typing import Any

from app.diagnostics._powershell import run_powershell
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

_DIAG_ID = "disk_health"

_WMI_QUERY = """
$disks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue
if ($disks) {
    $disks | Select-Object DeviceID,Model,InterfaceType,MediaType,Size,SerialNumber,Status,OperationalStatus,HealthStatus,PredictiveFailure,SMARTTemperature | ConvertTo-Json -Compress
} else {
    Get-CimInstance MSFT_PhysicalDisk -ErrorAction SilentlyContinue |
        Select-Object DeviceId,Model,MediaType,Size,OperationalStatus,HealthStatus,PredictiveFailure |
        ConvertTo-Json -Compress
}
"""


def _parse_disk(raw: Any) -> dict[str, Any]:
    """Parse a single disk WMI record into a normalized dict."""
    if not isinstance(raw, dict):
        return {}

    size_raw = raw.get("Size") or raw.get("FileSize")
    size_bytes = int(size_raw) if size_raw and str(size_raw).isdigit() else None

    serial_raw = raw.get("SerialNumber") or raw.get("SerialNumberExpr")
    serial_present = bool(serial_raw and str(serial_raw).strip())

    operational = raw.get("OperationalStatus")
    if isinstance(operational, list):
        operational = operational[0] if operational else None

    health = raw.get("HealthStatus")
    predictive = raw.get("PredictiveFailure")

    temp_raw = raw.get("SMARTTemperature") or raw.get("Temperature")
    temperature = None
    if temp_raw is not None:
        try:
            temperature = int(temp_raw)
        except (ValueError, TypeError):
            pass

    return {
        "device_id": raw.get("DeviceID") or raw.get("DeviceId", ""),
        "model": raw.get("Model", "Unknown"),
        "interface_type": raw.get("InterfaceType", "Unknown"),
        "media_type": raw.get("MediaType", "Unknown"),
        "size_bytes": size_bytes,
        "serial_number_present": serial_present,
        "operational_status": str(operational) if operational else "Unknown",
        "health_status": str(health) if health is not None else "unavailable",
        "predictive_failure": str(predictive) if predictive is not None else "unavailable",
        "smart_temperature": temperature,
    }


def collect_disk_health() -> list[DiagnosticResult]:
    """Collect disk health information from Windows WMI/CIM."""
    results: list[DiagnosticResult] = []

    if platform.system() != "Windows":
        results.append(DiagnosticResult(
            diagnostic_id=_DIAG_ID,
            category=DiagnosticCategory.DISK,
            status=DiagnosticStatus.NOT_SUPPORTED,
            title="Disk health",
            summary="Disk health diagnostics are not supported on this platform.",
            source="platform_check",
        ))
        return results

    raw, error = run_powershell(_WMI_QUERY)

    if error:
        results.append(DiagnosticResult(
            diagnostic_id=_DIAG_ID,
            category=DiagnosticCategory.DISK,
            status=DiagnosticStatus.FAILED,
            title="Disk health",
            summary=f"Failed to query disk health: {error}",
            source="Win32_DiskDrive",
            errors=[error],
        ))
        return results

    if raw is None:
        results.append(DiagnosticResult(
            diagnostic_id=_DIAG_ID,
            category=DiagnosticCategory.DISK,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Disk health",
            summary="No disk health information was returned by Windows.",
            source="Win32_DiskDrive",
            limitations=["WMI returned no data for Win32_DiskDrive."],
        ))
        return results

    items = raw if isinstance(raw, list) else [raw]

    for idx, item in enumerate(items):
        parsed = _parse_disk(item)
        if not parsed:
            continue

        device_id = parsed.get("device_id", f"disk_{idx}")
        health = parsed.get("health_status", "unavailable")
        predictive = parsed.get("predictive_failure", "unavailable")

        if health.lower() in ("critical", "error", "failed"):
            status = DiagnosticStatus.CRITICAL
        elif predictive.lower() == "yes":
            status = DiagnosticStatus.CRITICAL
        elif health.lower() in ("warning", "degraded"):
            status = DiagnosticStatus.WARNING
        elif health.lower() == "unavailable":
            status = DiagnosticStatus.UNAVAILABLE
        else:
            status = DiagnosticStatus.OK

        smart_available = health.lower() not in ("unavailable", "unknown", "")

        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_{device_id}",
            category=DiagnosticCategory.DISK,
            status=status,
            title=f"Disk: {parsed.get('model', device_id)}",
            summary=(
                f"Health: {health}, Predictive failure: {predictive}, "
                f"Operational: {parsed.get('operational_status', 'Unknown')}"
            ),
            evidence=parsed,
            source="Win32_DiskDrive",
            limitations=[
                "SMART attribute details not available through WMI.",
                "Temperature reading may be unavailable on some hardware.",
            ] if not smart_available else [],
        ))

    if not results:
        results.append(DiagnosticResult(
            diagnostic_id=_DIAG_ID,
            category=DiagnosticCategory.DISK,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Disk health",
            summary="No physical disks were detected.",
            source="Win32_DiskDrive",
        ))

    return results
