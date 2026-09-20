"""Read-only driver/version consistency diagnostics.

Checks driver dates, versions, and consistency through WMI.
Uses a SINGLE cached WMI query for both age and error checks.
Does NOT modify drivers, does NOT install updates, does NOT change
driver settings.
"""

from __future__ import annotations

import platform
from typing import Any

from app.diagnostics._powershell import run_powershell
from app.diagnostics.constants import DRIVER_AGE_WARN_DAYS, DRIVER_MAX_RETURNED
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

_DIAG_ID = "driver_consistency"


def _collect_all_driver_data() -> dict[str, Any] | None:
    """Collect ALL driver data in a single WMI query.

    Returns age summary and error summary derived from the same query.
    This avoids running 2 separate Win32_PnPEntity queries.
    """
    if platform.system() != "Windows":
        return None

    script = (
        f"$drivers = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DriverVersion -ne $null -and $_.DriverVersion -ne '' } | "
        f"Select-Object -First {DRIVER_MAX_RETURNED * 2}\n"
        "if ($drivers) {\n"
        "    $now = Get-Date\n"
        "    $outdated = @()\n"
        "    $total = 0\n"
        "    $with_date = 0\n"
        "    foreach ($d in $drivers) {\n"
        "        $total++\n"
        "        try {\n"
        "            $driverDate = [DateTime]::Parse($d.DriverDate)\n"
        "            $with_date++\n"
        f"            $ageDays = ($now - $driverDate).Days\n"
        f"            if ($ageDays -gt {DRIVER_AGE_WARN_DAYS}) {{\n"
        "                $outdated += @{\n"
        "                    name = $d.Name\n"
        "                    version = $d.DriverVersion\n"
        "                    date = $driverDate.ToString('yyyy-MM-dd')\n"
        "                    age_days = $ageDays\n"
        "                }\n"
        "            }\n"
        "        } catch {}\n"
        "    }\n"
        "    $errorDevices = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | "
        "    Where-Object { $_.ConfigManagerErrorCode -ne 0 } | "
        f"    Select-Object -First {DRIVER_MAX_RETURNED}\n"
        "    $errorTotal = 0\n"
        "    $byError = @()\n"
        "    if ($errorDevices) {\n"
        "        $grouped = $errorDevices | Group-Object -Property ConfigManagerErrorCode | "
        "        Select-Object Name,Count | Sort-Object Count -Descending\n"
        "        $errorTotal = ($errorDevices | Measure-Object).Count\n"
        "        foreach ($g in $grouped) {\n"
        "            $byError += @{ code = [int]$g.Name; count = $g.Count }\n"
        "        }\n"
        "    }\n"
        "    $result = @{\n"
        "        total_drivers = $total\n"
        "        with_date = $with_date\n"
        "        outdated_count = ($outdated | Measure-Object).Count\n"
        "        outdated_top = ($outdated | Sort-Object age_days -Descending | Select-Object -First 10)\n"
        "        error_total = $errorTotal\n"
        "        by_error = $byError\n"
        "    }\n"
        "    ConvertTo-Json $result -Compress\n"
        "} else {\n"
        "    ConvertTo-Json @{ total_drivers = 0; with_date = 0; outdated_count = 0; "
        "    outdated_top = @(); error_total = 0; by_error = @() } -Compress\n"
        "}"
    )
    raw, error = run_powershell(script)
    if error or raw is None:
        return None

    item = raw if isinstance(raw, dict) else {}
    return {
        "total_drivers": item.get("total_drivers", 0),
        "with_date": item.get("with_date", 0),
        "outdated_count": item.get("outdated_count", 0),
        "outdated_top": item.get("outdated_top", []),
        "error_total": item.get("error_total", 0),
        "by_error": item.get("by_error", []),
    }


def collect_driver_consistency() -> list[DiagnosticResult]:
    """Collect driver consistency diagnostics.

    Uses a single WMI query for both age and error checks.
    """
    results: list[DiagnosticResult] = []

    if platform.system() != "Windows":
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_age",
            category=DiagnosticCategory.DRIVER_CONSISTENCY,
            status=DiagnosticStatus.NOT_SUPPORTED,
            title="Driver consistency",
            summary="Driver diagnostics are not supported on this platform.",
            source="platform_check",
        ))
        return results

    # Single WMI query for all driver data
    data = _collect_all_driver_data()
    if data is None:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_age",
            category=DiagnosticCategory.DRIVER_CONSISTENCY,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Driver age",
            summary="Driver information could not be collected.",
            source="Win32_PnPEntity",
        ))
        return results

    # Driver age summary (derived from cached data)
    total = data.get("total_drivers", 0)
    outdated = data.get("outdated_count", 0)
    top_outdated = data.get("outdated_top", [])[:3]
    outdated_summary = ", ".join(
        f"{d['name']}(v{d['version']}, {d['age_days']}d)" for d in top_outdated
    ) if top_outdated else "none"

    status = DiagnosticStatus.WARNING if outdated > 0 else DiagnosticStatus.OK
    results.append(DiagnosticResult(
        diagnostic_id=f"{_DIAG_ID}_age",
        category=DiagnosticCategory.DRIVER_CONSISTENCY,
        status=status,
        title="Driver age",
        summary=f"{total} drivers installed, {outdated} older than {DRIVER_AGE_WARN_DAYS} days. Oldest: {outdated_summary}",
        evidence=data,
        source="Win32_PnPEntity",
        limitations=[f"Bounded to {DRIVER_MAX_RETURNED} drivers checked."],
    ))

    # Driver errors (derived from same query)
    total_errors = data.get("error_total", 0)
    by_error = data.get("by_error", [])
    error_summary = ", ".join(
        f"code {e['code']}({e['count']})" for e in by_error[:3]
    ) if by_error else "none"

    status = DiagnosticStatus.WARNING if total_errors > 0 else DiagnosticStatus.OK
    results.append(DiagnosticResult(
        diagnostic_id=f"{_DIAG_ID}_errors",
        category=DiagnosticCategory.DRIVER_CONSISTENCY,
        status=status,
        title="Driver errors",
        summary=f"{total_errors} device(s) with driver errors. Distribution: {error_summary}",
        evidence={"error_total": total_errors, "by_error": by_error},
        source="Win32_PnPEntity/ConfigManager",
    ))

    return results
