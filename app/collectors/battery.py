"""Read-only battery health snapshot with WMI enrichment on Windows.

Data sources (all read-only, no modifications):
  - psutil.sensors_battery()     : percent, plugged_in, seconds_left
  - Win32_PortableBattery (WMI)  : DesignCapacity, FullChargeCapacity,
                                   CycleCount, Name, Manufacturer, Chemistry
  - Win32_Battery (WMI fallback) : Name, Chemistry, EstimatedChargeRemaining

Capacity units: milliwatt-hours (mWh) where WMI provides energy capacity.
Health/wear are only calculated when both design and full-charge capacity
are available and design capacity is non-zero.

Privacy: serial_number is never stored. Only serial_number_present (bool)
is recorded.
"""

from __future__ import annotations

import json
import platform
import subprocess
from typing import Any

import psutil

from app.collectors.result import CollectorResult

# -- Status normalization ---------------------------------------------------

# psutil secsleft special values
_PSUTIL_CHARGING = -1
_PSUTIL_UNKNOWN = -2

# Normalized battery status values
STATUS_CHARGING = "charging"
STATUS_DISCHARGING = "discharging"
STATUS_FULL = "full"
STATUS_UNKNOWN = "unknown"
STATUS_UNAVAILABLE = "unavailable"


def _normalize_status(plugged_in: bool, seconds_left: int, percent: float) -> str:
    """Normalize raw psutil values into an explicit status string.

    Does NOT assume plugged_in == charging.
    """
    if plugged_in and percent >= 100.0:
        return STATUS_FULL
    if plugged_in and seconds_left == _PSUTIL_CHARGING:
        return STATUS_CHARGING
    if not plugged_in and seconds_left > 0:
        return STATUS_DISCHARGING
    if not plugged_in and seconds_left in (_PSUTIL_UNKNOWN, _PSUTIL_CHARGING):
        return STATUS_DISCHARGING
    if plugged_in:
        return STATUS_CHARGING
    return STATUS_UNKNOWN


# -- Health / wear calculation ---------------------------------------------

def _calculate_health(
    design_capacity: int | float | None,
    full_charge_capacity: int | float | None,
) -> tuple[float | None, float | None, str | None]:
    """Calculate health_percent and wear_percent from capacity data.

    Returns (health_percent, wear_percent, error_or_none).
    Only returns values when both capacities are available and design > 0.
    """
    if design_capacity is None or full_charge_capacity is None:
        return None, None, "capacity data unavailable"
    try:
        design = float(design_capacity)
        full = float(full_charge_capacity)
    except (TypeError, ValueError):
        return None, None, "capacity values not numeric"
    if design <= 0:
        return None, None, "design capacity is zero or negative"
    health = (full / design) * 100.0
    health = max(0.0, min(100.0, health))
    wear = 100.0 - health
    return round(health, 1), round(wear, 1), None


# -- WMI collection --------------------------------------------------------

def _powershell_json(script: str) -> tuple[object | None, str | None]:
    """Run a read-only PowerShell query and parse its JSON output.

    Returns a tuple of (result, error_message). On success error_message is
    None. On failure result is None and error_message describes the problem.
    """
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        return None, "powershell.exe not found"
    except subprocess.TimeoutExpired:
        return None, "PowerShell command timed out after 15s"
    except (subprocess.SubprocessError, OSError) as exc:
        return None, f"PowerShell subprocess error: {exc}"

    if completed.returncode != 0:
        return None, f"PowerShell exited with code {completed.returncode}"
    if not completed.stdout.strip():
        return None, "PowerShell returned empty output"

    try:
        return json.loads(completed.stdout, strict=False), None
    except json.JSONDecodeError as exc:
        return None, f"JSON parse error: {exc}"


def _collect_wmi_battery() -> dict[str, Any] | None:
    """Collect detailed battery data from WMI on Windows.

    Prefers Win32_PortableBattery (has DesignCapacity, FullChargeCapacity,
    CycleCount). Falls back to Win32_Battery for limited info.

    Returns a flat dict with normalized keys, or None if not available.
    """
    if platform.system() != "Windows":
        return None

    # -- Win32_PortableBattery (preferred) ----------------------------------
    result, error = _powershell_json(
        "Get-CimInstance Win32_PortableBattery | "
        "Select-Object Name,Manufacturer,Chemistry,DesignCapacity,"
        "FullChargeCapacity,CycleCount,SerialNumber | "
        "ConvertTo-Json -Compress"
    )
    if error is None and result is not None:
        items = result if isinstance(result, list) else [result]
        if items:
            bat = items[0]
            return {
                "source": "Win32_PortableBattery",
                "name": bat.get("Name"),
                "manufacturer": bat.get("Manufacturer"),
                "chemistry": _normalize_chemistry(bat.get("Chemistry")),
                "design_capacity_mwh": _safe_int(bat.get("DesignCapacity")),
                "full_charge_capacity_mwh": _safe_int(bat.get("FullChargeCapacity")),
                "cycle_count": _safe_int(bat.get("CycleCount")),
                "serial_number_present": bat.get("SerialNumber") is not None,
            }

    # -- Win32_Battery (fallback) -------------------------------------------
    result, error = _powershell_json(
        "Get-CimInstance Win32_Battery | "
        "Select-Object Name,Chemistry,EstimatedChargeRemaining | "
        "ConvertTo-Json -Compress"
    )
    if error is None and result is not None:
        items = result if isinstance(result, list) else [result]
        if items:
            bat = items[0]
            return {
                "source": "Win32_Battery",
                "name": bat.get("Name"),
                "manufacturer": None,
                "chemistry": _normalize_chemistry(bat.get("Chemistry")),
                "design_capacity_mwh": None,
                "full_charge_capacity_mwh": None,
                "cycle_count": None,
                "serial_number_present": False,
            }

    return None


# -- Helpers ----------------------------------------------------------------

_CHEMISTRY_MAP: dict[int, str] = {
    1: "Other",
    2: "Unknown",
    3: "Lead Acid",
    4: "Nickel Cadmium",
    5: "Nickel Metal Hydride",
    6: "Lithium Ion",
    7: "Zinc Air",
    8: "Zinc Carbon",
}


def _normalize_chemistry(raw: Any) -> str | None:
    """Convert WMI Chemistry integer to human-readable string."""
    if raw is None:
        return None
    try:
        return _CHEMISTRY_MAP.get(int(raw), f"Unknown ({raw})")
    except (TypeError, ValueError):
        return str(raw) if raw else None


def _safe_int(val: Any) -> int | None:
    """Safely convert a value to int, returning None on failure."""
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


# -- Main collector --------------------------------------------------------

def collect_result() -> CollectorResult:
    """Collect battery data from psutil + WMI enrichment.

    Base fields come from psutil (always available cross-platform).
    Enrichment fields come from WMI on Windows (absent on desktops
    without batteries or in VMs).

    Payload structure:
      available          : bool
      percent            : float (0-100, current charge level)
      plugged_in         : bool
      seconds_left       : int (-1=charging, -2=unknown, >=0=seconds)
      status             : str (normalized: charging/discharging/full/unknown)
      design_capacity_mwh   : int | None (mWh, from WMI)
      full_charge_capacity_mwh : int | None (mWh, from WMI)
      remaining_capacity_mwh  : calculated from percent * design / 100
      cycle_count        : int | None
      battery_name       : str | None
      manufacturer       : str | None
      chemistry          : str | None (human-readable)
      serial_number_present : bool (never stores actual serial)
      health_percent     : float | None (0-100, only when calculable)
      wear_percent       : float | None (0-100, only when calculable)
      health_status      : str (good/degraded/critical/unknown)
      wmi_source         : str | None ("Win32_PortableBattery" or "Win32_Battery")
    """
    battery = psutil.sensors_battery()
    if battery is None:
        return CollectorResult(payload={"available": False}, status="ok")

    percent = battery.percent
    plugged_in = battery.power_plugged
    seconds_left = battery.secsleft

    status = _normalize_status(plugged_in, seconds_left, percent)

    payload: dict[str, Any] = {
        "available": True,
        "percent": percent,
        "plugged_in": plugged_in,
        "seconds_left": seconds_left,
        "status": status,
        # Capacity defaults (may be overwritten by WMI)
        "design_capacity_mwh": None,
        "full_charge_capacity_mwh": None,
        "remaining_capacity_mwh": None,
        "cycle_count": None,
        "battery_name": None,
        "manufacturer": None,
        "chemistry": None,
        "serial_number_present": False,
        # Health defaults
        "health_percent": None,
        "wear_percent": None,
        "health_status": "unknown",
        "wmi_source": None,
    }

    # -- WMI enrichment (Windows only) --------------------------------------
    wmi_data = _collect_wmi_battery()
    if wmi_data is not None:
        payload["wmi_source"] = wmi_data.get("source")
        payload["battery_name"] = wmi_data.get("name")
        payload["manufacturer"] = wmi_data.get("manufacturer")
        payload["chemistry"] = wmi_data.get("chemistry")
        payload["design_capacity_mwh"] = wmi_data.get("design_capacity_mwh")
        payload["full_charge_capacity_mwh"] = wmi_data.get("full_charge_capacity_mwh")
        payload["cycle_count"] = wmi_data.get("cycle_count")
        payload["serial_number_present"] = wmi_data.get("serial_number_present", False)

        # -- Calculate remaining capacity from percent + design -----------
        design = wmi_data.get("design_capacity_mwh")
        if design is not None and percent is not None:
            payload["remaining_capacity_mwh"] = round(design * percent / 100.0)

        # -- Health / wear -----------------------------------------------
        health, wear, _err = _calculate_health(
            wmi_data.get("design_capacity_mwh"),
            wmi_data.get("full_charge_capacity_mwh"),
        )
        payload["health_percent"] = health
        payload["wear_percent"] = wear
        payload["health_status"] = _health_status_label(health)

    return CollectorResult(payload=payload, status="ok")


def _health_status_label(health_percent: float | None) -> str:
    """Map health_percent to a human-readable status label.

    Thresholds (informational only):
      >= 80%  : good
      >= 60%  : degraded
      < 60%   : critical
      None    : unknown (data unavailable)
    """
    if health_percent is None:
        return "unknown"
    if health_percent >= 80.0:
        return "good"
    if health_percent >= 60.0:
        return "degraded"
    return "critical"
