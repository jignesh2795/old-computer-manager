"""Battery analyzer -- identifies battery health conditions from snapshots.

This analyzer distinguishes between:
  - "data unavailable" (capacity fields missing, battery not present)
  - "battery health is degraded" (capacity data exists and shows wear)

It does NOT:
  - Call a battery defective because percent is low
  - Call a battery defective because it is plugged in
  - Call a battery defective because seconds_left is unknown
  - Infer health from charge percentage
  - Make health claims when capacity data is absent
"""

from __future__ import annotations

from typing import Any

from app.analyzers.constants import (
    BATTERY_HEALTH_DEGRADED_THRESHOLD,
    BATTERY_HEALTH_GOOD_THRESHOLD,
)
from app.analyzers.finding import Finding


name = "battery"


def analyze(snapshots: dict[str, Any]) -> list[Finding]:
    """Analyze battery snapshot for health conditions.

    Produces findings only when the battery is present AND enough data
    exists to make an evidence-supported claim.
    """
    payload = snapshots.get("battery")
    if not payload or not isinstance(payload, dict):
        return []

    # Battery not present on this machine -- nothing to analyze
    if not payload.get("available"):
        return []

    findings: list[Finding] = []

    # -- Gather key fields ---------------------------------------------------
    health_status = payload.get("health_status", "unknown")
    health_percent = payload.get("health_percent")
    wear_percent = payload.get("wear_percent")
    design_cap = payload.get("design_capacity_mwh")
    full_charge_cap = payload.get("full_charge_capacity_mwh")
    cycle_count = payload.get("cycle_count")
    status = payload.get("status", "unknown")
    percent = payload.get("percent")
    battery_name = payload.get("battery_name")
    chemistry = payload.get("chemistry")
    wmi_source = payload.get("wmi_source")

    evidence_base: dict[str, Any] = {
        "percent": percent,
        "status": status,
        "health_percent": health_percent,
        "wear_percent": wear_percent,
        "health_status": health_status,
        "design_capacity_mwh": design_cap,
        "full_charge_capacity_mwh": full_charge_cap,
        "cycle_count": cycle_count,
        "battery_name": battery_name,
        "chemistry": chemistry,
        "wmi_source": wmi_source,
    }

    # -- Finding A: Health degraded ------------------------------------------
    if health_status == "degraded" and health_percent is not None:
        findings.append(
            Finding(
                analyzer=name,
                severity="warning",
                title=f"Battery health degraded ({health_percent:.1f}%)",
                message=(
                    f"Battery health is {health_percent:.1f}% of design capacity "
                    f"({wear_percent:.1f}% wear). "
                    f"Design capacity: {design_cap} mWh, "
                    f"full-charge capacity: {full_charge_cap} mWh. "
                    f"Battery age, temperature, calibration, and chemistry "
                    f"affect interpretation. This is informational only."
                ),
                evidence=evidence_base,
                recommendation=(
                    "Monitor battery health over successive discovery runs. "
                    "If health continues to decline, consider battery replacement. "
                    "Calibration may improve reported capacity if the battery "
                    "has not been recently calibrated."
                ),
            )
        )

    # -- Finding B: Health critical ------------------------------------------
    if health_status == "critical" and health_percent is not None:
        findings.append(
            Finding(
                analyzer=name,
                severity="critical",
                title=f"Battery health critical ({health_percent:.1f}%)",
                message=(
                    f"Battery health is {health_percent:.1f}% of design capacity "
                    f"({wear_percent:.1f}% wear). "
                    f"Design capacity: {design_cap} mWh, "
                    f"full-charge capacity: {full_charge_cap} mWh. "
                    f"The battery may not hold sufficient charge for normal use. "
                    f"Battery age, temperature, calibration, and chemistry "
                    f"affect interpretation."
                ),
                evidence=evidence_base,
                recommendation=(
                    "Battery replacement is likely needed. Run successive "
                    "discovery runs to confirm the trend. A battery calibration "
                    "cycle may provide more accurate readings."
                ),
            )
        )

    # -- Finding C: Capacity data unavailable --------------------------------
    if health_status == "unknown" and design_cap is None:
        findings.append(
            Finding(
                analyzer=name,
                severity="info",
                title="Battery capacity data unavailable",
                message=(
                    "The battery is present but Windows did not expose "
                    "design capacity or full-charge capacity through WMI. "
                    "Health cannot be calculated. "
                    f"WMI source: {wmi_source or 'none'}. "
                    "This may occur on desktops with emulated batteries, "
                    "VMs, or systems with limited ACPI/WMI support."
                ),
                evidence=evidence_base,
                recommendation=(
                    "This is informational only. No action is needed. "
                    "If the battery is a real removable battery, ensure "
                    " chipset and battery drivers are up to date."
                ),
            )
        )

    # -- Finding D: Battery reporting anomaly --------------------------------
    # Detect cases where the numbers are internally inconsistent
    if (
        design_cap is not None
        and full_charge_cap is not None
        and health_percent is not None
    ):
        # full_charge > design by more than 5% (reporting anomaly)
        if full_charge_cap > design_cap * 1.05:
            findings.append(
                Finding(
                    analyzer=name,
                    severity="warning",
                    title="Battery capacity reporting anomaly",
                    message=(
                        f"Full-charge capacity ({full_charge_cap} mWh) exceeds "
                        f"design capacity ({design_cap} mWh) by more than 5%. "
                        f"This may indicate a reporting anomaly or battery "
                        f"replacement. Health reported as {health_percent:.1f}%."
                    ),
                    evidence=evidence_base,
                    recommendation=(
                        "Verify the battery has not been recently replaced. "
                        "If the battery is original, the capacity reporting "
                        "may be inaccurate. Run successive discovery runs "
                        "to observe the trend."
                    ),
                )
            )

    return findings
