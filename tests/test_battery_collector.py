"""Tests for the battery collector.

All tests mock psutil and WMI to avoid requiring a real battery.
No real files or system settings are modified.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.collectors.battery import (
    STATUS_CHARGING,
    STATUS_DISCHARGING,
    STATUS_FULL,
    STATUS_UNKNOWN,
    _calculate_health,
    _normalize_status,
    collect_result,
)
from app.collectors.result import CollectorResult


# ── Status normalization ──────────────────────────────────────────────


class TestNormalizeStatus:
    def test_charging_when_plugged_not_full(self) -> None:
        assert _normalize_status(True, -1, 50.0) == STATUS_CHARGING

    def test_full_when_plugged_at_100(self) -> None:
        assert _normalize_status(True, -1, 100.0) == STATUS_FULL

    def test_full_when_plugged_at_100_positive_secs(self) -> None:
        assert _normalize_status(True, 3600, 100.0) == STATUS_FULL

    def test_discharging_when_unplugged_positive_secs(self) -> None:
        assert _normalize_status(False, 7200, 60.0) == STATUS_DISCHARGING

    def test_discharging_when_unplugged_unknown_secs(self) -> None:
        assert _normalize_status(False, -2, 60.0) == STATUS_DISCHARGING

    def test_discharging_when_unplugged_charging_secs(self) -> None:
        assert _normalize_status(False, -1, 60.0) == STATUS_DISCHARGING

    def test_charging_when_plugged_zero_percent(self) -> None:
        assert _normalize_status(True, -1, 0.0) == STATUS_CHARGING

    def test_unknown_when_plugged_positive_secs_not_full(self) -> None:
        # Edge case: plugged in, positive secs left, but not at 100%
        assert _normalize_status(True, 3600, 80.0) == STATUS_CHARGING


# ── Health calculation ────────────────────────────────────────────────


class TestCalculateHealth:
    def test_valid_health(self) -> None:
        health, wear, err = _calculate_health(50000, 40000)
        assert health == 80.0
        assert wear == 20.0
        assert err is None

    def test_full_health(self) -> None:
        health, wear, err = _calculate_health(50000, 50000)
        assert health == 100.0
        assert wear == 0.0

    def test_low_health(self) -> None:
        health, wear, err = _calculate_health(50000, 20000)
        assert health == 40.0
        assert wear == 60.0

    def test_clamped_above_100(self) -> None:
        health, wear, _ = _calculate_health(50000, 55000)
        assert health == 100.0
        assert wear == 0.0

    def test_clamped_below_0(self) -> None:
        health, wear, _ = _calculate_health(50000, -5000)
        assert health == 0.0
        assert wear == 100.0

    def test_zero_design_capacity(self) -> None:
        health, wear, err = _calculate_health(0, 0)
        assert health is None
        assert wear is None
        assert "zero" in err

    def test_negative_design_capacity(self) -> None:
        health, wear, err = _calculate_health(-100, 50)
        assert health is None
        assert "zero" in err

    def test_none_design_capacity(self) -> None:
        health, wear, err = _calculate_health(None, 50000)
        assert health is None
        assert "unavailable" in err

    def test_none_full_charge_capacity(self) -> None:
        health, wear, err = _calculate_health(50000, None)
        assert health is None
        assert "unavailable" in err

    def test_non_numeric_values(self) -> None:
        health, wear, err = _calculate_health("abc", "def")
        assert health is None
        assert "not numeric" in err

    def test_float_capacities(self) -> None:
        health, wear, err = _calculate_health(50000.5, 40000.2)
        assert health is not None
        assert wear is not None
        assert err is None


# ── Collector: battery unavailable ────────────────────────────────────


class TestBatteryUnavailable:
    @patch("app.collectors.battery.psutil")
    def test_no_battery_returns_available_false(self, mock_psutil: object) -> None:
        mock_psutil.sensors_battery.return_value = None  # type: ignore[attr-defined]
        result = collect_result()
        assert isinstance(result, CollectorResult)
        assert result.status == "ok"
        assert result.payload["available"] is False

    @patch("app.collectors.battery.psutil")
    def test_no_battery_no_wmi_fields(self, mock_psutil: object) -> None:
        mock_psutil.sensors_battery.return_value = None  # type: ignore[attr-defined]
        result = collect_result()
        assert "health_percent" not in result.payload or result.payload.get("health_percent") is None
        assert result.payload["available"] is False


# ── Collector: battery available ──────────────────────────────────────


def _make_battery(percent: float = 75.0, plugged: bool = False, secs: int = 3600):
    """Create a mock psutil battery object."""
    return SimpleNamespace(
        percent=percent,
        power_plugged=plugged,
        secsleft=secs,
    )


class TestBatteryAvailable:
    @patch("app.collectors.battery._collect_wmi_battery")
    @patch("app.collectors.battery.psutil")
    def test_basic_fields_without_wmi(self, mock_psutil: object, mock_wmi: object) -> None:
        mock_psutil.sensors_battery.return_value = _make_battery(  # type: ignore[attr-defined]
            percent=75.0, plugged=False, secs=3600
        )
        mock_wmi.return_value = None

        result = collect_result()
        assert result.status == "ok"
        p = result.payload
        assert p["available"] is True
        assert p["percent"] == 75.0
        assert p["plugged_in"] is False
        assert p["seconds_left"] == 3600
        assert p["status"] == STATUS_DISCHARGING
        assert p["design_capacity_mwh"] is None
        assert p["health_percent"] is None
        assert p["health_status"] == "unknown"

    @patch("app.collectors.battery._collect_wmi_battery")
    @patch("app.collectors.battery.psutil")
    def test_wmi_enrichment_with_capacity(
        self, mock_psutil: object, mock_wmi: object
    ) -> None:
        mock_psutil.sensors_battery.return_value = _make_battery(  # type: ignore[attr-defined]
            percent=80.0, plugged=True, secs=-1
        )
        mock_wmi.return_value = {
            "source": "Win32_PortableBattery",
            "name": "Test Battery",
            "manufacturer": "TestCorp",
            "chemistry": "Lithium Ion",
            "design_capacity_mwh": 50000,
            "full_charge_capacity_mwh": 40000,
            "cycle_count": 300,
            "serial_number_present": True,
        }

        result = collect_result()
        p = result.payload
        assert p["available"] is True
        assert p["design_capacity_mwh"] == 50000
        assert p["full_charge_capacity_mwh"] == 40000
        assert p["cycle_count"] == 300
        assert p["battery_name"] == "Test Battery"
        assert p["manufacturer"] == "TestCorp"
        assert p["chemistry"] == "Lithium Ion"
        assert p["serial_number_present"] is True
        assert p["wmi_source"] == "Win32_PortableBattery"
        # Health: 40000/50000 = 80%
        assert p["health_percent"] == 80.0
        assert p["wear_percent"] == 20.0
        assert p["health_status"] == "good"
        # Remaining: 80% of 50000 = 40000
        assert p["remaining_capacity_mwh"] == 40000

    @patch("app.collectors.battery._collect_wmi_battery")
    @patch("app.collectors.battery.psutil")
    def test_health_degraded(
        self, mock_psutil: object, mock_wmi: object
    ) -> None:
        mock_psutil.sensors_battery.return_value = _make_battery(  # type: ignore[attr-defined]
            percent=50.0, plugged=True, secs=-1
        )
        mock_wmi.return_value = {
            "source": "Win32_PortableBattery",
            "name": "Bat",
            "manufacturer": None,
            "chemistry": None,
            "design_capacity_mwh": 50000,
            "full_charge_capacity_mwh": 35000,
            "cycle_count": None,
            "serial_number_present": False,
        }

        result = collect_result()
        p = result.payload
        assert p["health_percent"] == 70.0
        assert p["wear_percent"] == 30.0
        assert p["health_status"] == "degraded"

    @patch("app.collectors.battery._collect_wmi_battery")
    @patch("app.collectors.battery.psutil")
    def test_health_critical(
        self, mock_psutil: object, mock_wmi: object
    ) -> None:
        mock_psutil.sensors_battery.return_value = _make_battery(  # type: ignore[attr-defined]
            percent=20.0, plugged=False, secs=600
        )
        mock_wmi.return_value = {
            "source": "Win32_PortableBattery",
            "name": "Bat",
            "manufacturer": None,
            "chemistry": None,
            "design_capacity_mwh": 50000,
            "full_charge_capacity_mwh": 25000,
            "cycle_count": 800,
            "serial_number_present": False,
        }

        result = collect_result()
        p = result.payload
        assert p["health_percent"] == 50.0
        assert p["health_status"] == "critical"

    @patch("app.collectors.battery._collect_wmi_battery")
    @patch("app.collectors.battery.psutil")
    def test_serial_number_never_stored(
        self, mock_psutil: object, mock_wmi: object
    ) -> None:
        mock_psutil.sensors_battery.return_value = _make_battery(  # type: ignore[attr-defined]
            percent=100.0, plugged=True, secs=-1
        )
        mock_wmi.return_value = {
            "source": "Win32_PortableBattery",
            "name": "Bat",
            "manufacturer": None,
            "chemistry": None,
            "design_capacity_mwh": None,
            "full_charge_capacity_mwh": None,
            "cycle_count": None,
            "serial_number_present": True,
        }

        result = collect_result()
        p = result.payload
        assert p["serial_number_present"] is True
        # The actual serial number string must never appear in the payload
        assert "serial_number" not in p or p.get("serial_number") is None

    @patch("app.collectors.battery._collect_wmi_battery")
    @patch("app.collectors.battery.psutil")
    def test_zero_design_capacity_no_health(
        self, mock_psutil: object, mock_wmi: object
    ) -> None:
        mock_psutil.sensors_battery.return_value = _make_battery(  # type: ignore[attr-defined]
            percent=100.0, plugged=True, secs=-1
        )
        mock_wmi.return_value = {
            "source": "Win32_PortableBattery",
            "name": "Bat",
            "manufacturer": None,
            "chemistry": None,
            "design_capacity_mwh": 0,
            "full_charge_capacity_mwh": 0,
            "cycle_count": None,
            "serial_number_present": False,
        }

        result = collect_result()
        p = result.payload
        assert p["health_percent"] is None
        assert p["health_status"] == "unknown"

    @patch("app.collectors.battery._collect_wmi_battery")
    @patch("app.collectors.battery.psutil")
    def test_cycle_count_unavailable(
        self, mock_psutil: object, mock_wmi: object
    ) -> None:
        mock_psutil.sensors_battery.return_value = _make_battery(  # type: ignore[attr-defined]
            percent=90.0, plugged=True, secs=-1
        )
        mock_wmi.return_value = {
            "source": "Win32_Battery",
            "name": "Bat",
            "manufacturer": None,
            "chemistry": None,
            "design_capacity_mwh": None,
            "full_charge_capacity_mwh": None,
            "cycle_count": None,
            "serial_number_present": False,
        }

        result = collect_result()
        assert result.payload["cycle_count"] is None
        assert result.payload["design_capacity_mwh"] is None

    @patch("app.collectors.battery._collect_wmi_battery")
    @patch("app.collectors.battery.psutil")
    def test_status_charging(
        self, mock_psutil: object, mock_wmi: object
    ) -> None:
        mock_psutil.sensors_battery.return_value = _make_battery(  # type: ignore[attr-defined]
            percent=50.0, plugged=True, secs=-1
        )
        mock_wmi.return_value = None
        result = collect_result()
        assert result.payload["status"] == STATUS_CHARGING

    @patch("app.collectors.battery._collect_wmi_battery")
    @patch("app.collectors.battery.psutil")
    def test_status_full(
        self, mock_psutil: object, mock_wmi: object
    ) -> None:
        mock_psutil.sensors_battery.return_value = _make_battery(  # type: ignore[attr-defined]
            percent=100.0, plugged=True, secs=-1
        )
        mock_wmi.return_value = None
        result = collect_result()
        assert result.payload["status"] == STATUS_FULL


# ── Collector: platform not Windows ──────────────────────────────────


class TestPlatformNotWindows:
    @patch("app.collectors.battery.platform")
    def test_wmi_returns_none_on_non_windows(self, mock_platform: object) -> None:
        mock_platform.system.return_value = "Linux"  # type: ignore[attr-defined]
        # _collect_wmi_battery should return None, but collect_result
        # still works (psutil battery on Linux would require mocking)
        from app.collectors.battery import _collect_wmi_battery
        assert _collect_wmi_battery() is None
