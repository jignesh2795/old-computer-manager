"""Read-only battery health snapshot."""

from __future__ import annotations

import psutil


def collect() -> dict[str, object]:
    battery = psutil.sensors_battery()
    if battery is None:
        return {"available": False}
    return {
        "available": True,
        "percent": battery.percent,
        "plugged_in": battery.power_plugged,
        "seconds_left": battery.secsleft,
    }
