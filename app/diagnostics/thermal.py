"""Read-only thermal diagnostics.

Collects CPU, system/board, and GPU temperatures where the OS exposes them.
Does NOT install third-party hardware-monitoring software.
If temperature is unavailable, explicitly reports unavailable.
Does NOT infer temperature from CPU load or fan behavior.
"""

from __future__ import annotations

import platform
from typing import Any

from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

_DIAG_ID = "thermal"


def _collect_psutil_temperatures() -> dict[str, Any] | None:
    """Collect temperatures via psutil.sensors_temperatures() if available."""
    try:
        import psutil
    except ImportError:
        return None

    if not hasattr(psutil, "sensors_temperatures"):
        return None

    try:
        temps = psutil.sensors_temperatures()
    except (AttributeError, RuntimeError, OSError):
        return None

    if not temps:
        return None

    result: dict[str, Any] = {}
    for name, entries in temps.items():
        if not entries:
            continue
        readings = []
        for entry in entries:
            readings.append({
                "label": getattr(entry, "label", name),
                "current": entry.current,
                "high": entry.high,
                "critical": entry.critical,
                "unit": "C",
            })
        if readings:
            result[name] = readings

    return result if result else None


def _collect_wmi_temperatures() -> dict[str, Any] | None:
    """Collect temperatures via WMI if available on Windows."""
    if platform.system() != "Windows":
        return None

    from app.diagnostics._powershell import run_powershell

    script = (
        "$temps = Get-CimInstance MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue\n"
        "if ($temps) {\n"
        "    $temps | Select-Object InstanceName,CurrentTemperature,Temperature |\n"
        "        ConvertTo-Json -Compress\n"
        "}"
    )
    raw, error = run_powershell(script)

    if error or raw is None:
        return None

    items = raw if isinstance(raw, list) else [raw]
    result: dict[str, Any] = {}

    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("InstanceName", "thermal_zone")
        temp_raw = item.get("CurrentTemperature") or item.get("Temperature")
        if temp_raw is not None:
            try:
                temp_k = float(temp_raw) / 10.0
                temp_c = temp_k - 273.15
                result[name] = [{
                    "label": name,
                    "current": round(temp_c, 1),
                    "high": None,
                    "critical": None,
                    "unit": "C",
                }]
            except (ValueError, TypeError, ZeroDivisionError):
                pass

    return result if result else None


def collect_thermal() -> list[DiagnosticResult]:
    """Collect thermal information from available sources."""
    results: list[DiagnosticResult] = []

    psutil_temps = _collect_psutil_temperatures()
    wmi_temps = _collect_wmi_temperatures() if platform.system() == "Windows" else None

    all_temps: dict[str, Any] = {}
    sources: list[str] = []

    if psutil_temps:
        all_temps.update(psutil_temps)
        sources.append("psutil")

    if wmi_temps:
        for key, val in wmi_temps.items():
            if key not in all_temps:
                all_temps[key] = val
        sources.append("MSAcpi_ThermalZoneTemperature")

    if not all_temps:
        results.append(DiagnosticResult(
            diagnostic_id=_DIAG_ID,
            category=DiagnosticCategory.THERMAL,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Thermal information",
            summary="No temperature sensors were detected by the operating system.",
            source="psutil/WMI",
            limitations=[
                "This machine may not expose temperature sensors through the OS.",
                "Third-party hardware monitoring software was NOT installed.",
            ],
        ))
        return results

    source_str = " + ".join(sources)

    for zone_name, readings in all_temps.items():
        for reading in readings:
            current = reading.get("current")
            high = reading.get("high")
            critical = reading.get("critical")
            label = reading.get("label", zone_name)

            if current is None:
                status = DiagnosticStatus.UNAVAILABLE
            elif critical is not None and current >= critical:
                status = DiagnosticStatus.CRITICAL
            elif high is not None and current >= high:
                status = DiagnosticStatus.WARNING
            else:
                status = DiagnosticStatus.OK

            evidence: dict[str, Any] = {
                "zone": zone_name,
                "label": label,
                "current_celsius": current,
                "high_threshold": high,
                "critical_threshold": critical,
            }

            summary_parts = [f"Current: {current} C" if current is not None else "Current: unavailable"]
            if high is not None:
                summary_parts.append(f"High: {high} C")
            if critical is not None:
                summary_parts.append(f"Critical: {critical} C")

            results.append(DiagnosticResult(
                diagnostic_id=f"{_DIAG_ID}_{zone_name}",
                category=DiagnosticCategory.THERMAL,
                status=status,
                title=f"Temperature: {label}",
                summary=", ".join(summary_parts),
                evidence=evidence,
                source=source_str,
            ))

    return results
