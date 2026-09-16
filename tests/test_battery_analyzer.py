"""Tests for the battery analyzer.

All tests use mocked snapshot data. No real battery or system modifications.
"""

from __future__ import annotations

from app.analyzers import battery_analyzer
from app.analyzers.finding import Finding


# ── No battery / not available ────────────────────────────────────────


class TestNoBattery:
    def test_empty_snapshots(self) -> None:
        assert battery_analyzer.analyze({}) == []

    def test_battery_not_available(self) -> None:
        snaps = {"battery": {"available": False}}
        assert battery_analyzer.analyze(snaps) == []

    def test_battery_none_payload(self) -> None:
        snaps = {"battery": None}
        assert battery_analyzer.analyze(snaps) == []

    def test_battery_list_payload(self) -> None:
        snaps = {"battery": [{"available": True}]}
        assert battery_analyzer.analyze(snaps) == []


# ── Health good ───────────────────────────────────────────────────────


class TestHealthGood:
    def test_no_findings_for_good_health(self) -> None:
        snaps = {
            "battery": {
                "available": True,
                "percent": 85.0,
                "plugged_in": True,
                "seconds_left": -1,
                "status": "charging",
                "design_capacity_mwh": 50000,
                "full_charge_capacity_mwh": 45000,
                "cycle_count": 100,
                "health_percent": 90.0,
                "wear_percent": 10.0,
                "health_status": "good",
                "battery_name": "Test Battery",
                "chemistry": "Lithium Ion",
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        assert findings == []

    def test_no_findings_at_exactly_80_percent(self) -> None:
        snaps = {
            "battery": {
                "available": True,
                "percent": 50.0,
                "plugged_in": True,
                "seconds_left": -1,
                "status": "charging",
                "design_capacity_mwh": 50000,
                "full_charge_capacity_mwh": 40000,
                "cycle_count": 200,
                "health_percent": 80.0,
                "wear_percent": 20.0,
                "health_status": "good",
                "battery_name": None,
                "chemistry": None,
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        assert findings == []


# ── Health degraded ───────────────────────────────────────────────────


class TestHealthDegraded:
    def test_degraded_health_returns_warning(self) -> None:
        snaps = {
            "battery": {
                "available": True,
                "percent": 50.0,
                "plugged_in": True,
                "seconds_left": -1,
                "status": "charging",
                "design_capacity_mwh": 50000,
                "full_charge_capacity_mwh": 35000,
                "cycle_count": 500,
                "health_percent": 70.0,
                "wear_percent": 30.0,
                "health_status": "degraded",
                "battery_name": "Old Battery",
                "chemistry": "Lithium Ion",
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, Finding)
        assert f.analyzer == "battery"
        assert f.severity == "warning"
        assert "70.0%" in f.title
        assert f.evidence["health_percent"] == 70.0
        assert f.evidence["design_capacity_mwh"] == 50000

    def test_degraded_at_exactly_60_percent(self) -> None:
        snaps = {
            "battery": {
                "available": True,
                "percent": 40.0,
                "plugged_in": False,
                "seconds_left": 600,
                "status": "discharging",
                "design_capacity_mwh": 50000,
                "full_charge_capacity_mwh": 30000,
                "cycle_count": None,
                "health_percent": 60.0,
                "wear_percent": 40.0,
                "health_status": "degraded",
                "battery_name": None,
                "chemistry": None,
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        assert len(findings) == 1
        assert findings[0].severity == "warning"


# ── Health critical ───────────────────────────────────────────────────


class TestHealthCritical:
    def test_critical_health_returns_critical(self) -> None:
        snaps = {
            "battery": {
                "available": True,
                "percent": 10.0,
                "plugged_in": False,
                "seconds_left": 300,
                "status": "discharging",
                "design_capacity_mwh": 50000,
                "full_charge_capacity_mwh": 20000,
                "cycle_count": 1000,
                "health_percent": 40.0,
                "wear_percent": 60.0,
                "health_status": "critical",
                "battery_name": "Dying Battery",
                "chemistry": "Lithium Ion",
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "critical"
        assert "40.0%" in f.title
        assert f.evidence["health_percent"] == 40.0

    def test_just_below_60_is_critical(self) -> None:
        snaps = {
            "battery": {
                "available": True,
                "percent": 25.0,
                "plugged_in": True,
                "seconds_left": -1,
                "status": "charging",
                "design_capacity_mwh": 50000,
                "full_charge_capacity_mwh": 29900,
                "cycle_count": None,
                "health_percent": 59.8,
                "wear_percent": 40.2,
                "health_status": "critical",
                "battery_name": None,
                "chemistry": None,
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        assert len(findings) == 1
        assert findings[0].severity == "critical"


# ── Capacity data unavailable ─────────────────────────────────────────


class TestCapacityDataUnavailable:
    def test_info_finding_when_capacity_missing(self) -> None:
        snaps = {
            "battery": {
                "available": True,
                "percent": 0.0,
                "plugged_in": True,
                "seconds_left": -1,
                "status": "charging",
                "design_capacity_mwh": None,
                "full_charge_capacity_mwh": None,
                "cycle_count": None,
                "health_percent": None,
                "wear_percent": None,
                "health_status": "unknown",
                "battery_name": None,
                "chemistry": None,
                "wmi_source": "Win32_Battery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "info"
        assert "unavailable" in f.title.lower()
        assert f.evidence["design_capacity_mwh"] is None


# ── Low charge does NOT equal degraded health ─────────────────────────


class TestLowChargeNotDegraded:
    def test_low_percent_with_good_health_no_finding(self) -> None:
        """Battery at 5% charge but health is 95% -- no health finding."""
        snaps = {
            "battery": {
                "available": True,
                "percent": 5.0,
                "plugged_in": False,
                "seconds_left": 300,
                "status": "discharging",
                "design_capacity_mwh": 50000,
                "full_charge_capacity_mwh": 47500,
                "cycle_count": 50,
                "health_percent": 95.0,
                "wear_percent": 5.0,
                "health_status": "good",
                "battery_name": "Healthy Battery",
                "chemistry": "Lithium Ion",
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        # No degraded/critical health finding -- only good health
        assert findings == []

    def test_zero_percent_good_health_no_finding(self) -> None:
        """Battery at 0% but health is 85% -- no health finding."""
        snaps = {
            "battery": {
                "available": True,
                "percent": 0.0,
                "plugged_in": True,
                "seconds_left": -1,
                "status": "charging",
                "design_capacity_mwh": 50000,
                "full_charge_capacity_mwh": 42500,
                "cycle_count": 100,
                "health_percent": 85.0,
                "wear_percent": 15.0,
                "health_status": "good",
                "battery_name": None,
                "chemistry": None,
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        assert findings == []


# ── Dead old battery reading does not create false health finding ─────


class TestDeadBatteryNoFalseFinding:
    def test_dead_battery_with_no_capacity_data(self) -> None:
        """Current dead battery: 0%, plugged, no WMI capacity data.

        Must NOT produce a degraded/critical health finding.
        Only the 'capacity data unavailable' info finding is acceptable.
        """
        snaps = {
            "battery": {
                "available": True,
                "percent": 0.0,
                "plugged_in": True,
                "seconds_left": -1,
                "status": "charging",
                "design_capacity_mwh": None,
                "full_charge_capacity_mwh": None,
                "cycle_count": None,
                "health_percent": None,
                "wear_percent": None,
                "health_status": "unknown",
                "battery_name": None,
                "chemistry": None,
                "wmi_source": None,
            }
        }
        findings = battery_analyzer.analyze(snaps)
        # Only info-level 'capacity data unavailable', NOT warning/critical
        for f in findings:
            assert f.severity == "info"
            assert "unavailable" in f.title.lower()

    def test_dead_battery_with_zero_capacity(self) -> None:
        """Dead battery with WMI reporting 0/0 capacity.

        Must NOT produce degraded/critical health finding.
        """
        snaps = {
            "battery": {
                "available": True,
                "percent": 0.0,
                "plugged_in": True,
                "seconds_left": -1,
                "status": "charging",
                "design_capacity_mwh": 0,
                "full_charge_capacity_mwh": 0,
                "cycle_count": None,
                "health_percent": None,
                "wear_percent": None,
                "health_status": "unknown",
                "battery_name": "Dead Battery",
                "chemistry": "Lithium Ion",
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        for f in findings:
            assert f.severity == "info"


# ── Battery reporting anomaly ─────────────────────────────────────────


class TestReportingAnomaly:
    def test_full_charge_exceeds_design(self) -> None:
        snaps = {
            "battery": {
                "available": True,
                "percent": 100.0,
                "plugged_in": True,
                "seconds_left": -1,
                "status": "full",
                "design_capacity_mwh": 50000,
                "full_charge_capacity_mwh": 55000,
                "cycle_count": None,
                "health_percent": 100.0,
                "wear_percent": 0.0,
                "health_status": "good",
                "battery_name": None,
                "chemistry": None,
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        # Should have the anomaly finding (warning)
        anomaly = [f for f in findings if "anomaly" in f.title.lower()]
        assert len(anomaly) == 1
        assert anomaly[0].severity == "warning"

    def test_full_charge_slightly_above_design_no_anomaly(self) -> None:
        """Within 5% tolerance -- no anomaly finding."""
        snaps = {
            "battery": {
                "available": True,
                "percent": 100.0,
                "plugged_in": True,
                "seconds_left": -1,
                "status": "full",
                "design_capacity_mwh": 50000,
                "full_charge_capacity_mwh": 52000,
                "cycle_count": None,
                "health_percent": 100.0,
                "wear_percent": 0.0,
                "health_status": "good",
                "battery_name": None,
                "chemistry": None,
                "wmi_source": "Win32_PortableBattery",
            }
        }
        findings = battery_analyzer.analyze(snaps)
        anomaly = [f for f in findings if "anomaly" in f.title.lower()]
        assert len(anomaly) == 0


# ── Latest completed run behavior ─────────────────────────────────────


class TestLatestCompletedRun:
    def test_analyzer_returns_empty_for_missing_battery_key(self) -> None:
        """Snapshots dict without 'battery' key -- analyzer returns []."""
        snaps = {"storage": [], "processes": []}
        assert battery_analyzer.analyze(snaps) == []

    def test_analyzer_with_empty_battery_dict(self) -> None:
        snaps = {"battery": {}}
        assert battery_analyzer.analyze(snaps) == []
