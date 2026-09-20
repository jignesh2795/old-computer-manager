"""Read-only Windows reliability and crash-history diagnostics.

Enhanced reliability tracking beyond the basic Win32_ReliabilityRecord
in windows_health. Uses a SINGLE cached WMI query and derives all
results from it. Does NOT modify event logs or reliability settings.
"""

from __future__ import annotations

import platform
from typing import Any

from app.diagnostics._powershell import run_powershell
from app.diagnostics.constants import (
    RELIABILITY_CRASH_WARN_THRESHOLD,
    RELIABILITY_LOOKBACK_DAYS,
    RELIABILITY_MAX_EVENTS,
)
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

_DIAG_ID = "reliability"


def _collect_all_reliability_records() -> dict[str, Any] | None:
    """Collect ALL reliability records in a single WMI query.

    Returns the raw grouped data used by all three result types.
    This avoids running 3 separate Win32_ReliabilityRecord queries.
    """
    if platform.system() != "Windows":
        return None

    script = (
        f"$cutoff = (Get-Date).AddDays(-{RELIABILITY_LOOKBACK_DAYS})\n"
        f"$records = Get-CimInstance Win32_ReliabilityRecord -ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.TimeGenerated -gt $cutoff }} | "
        f"Sort-Object -Property TimeGenerated -Descending | "
        f"Select-Object -First {RELIABILITY_MAX_EVENTS}\n"
        "if ($records) {\n"
        "    $total = ($records | Measure-Object).Count\n"
        "    $byType = $records | Group-Object -Property EventType | "
        "    Select-Object Name,Count | Sort-Object Count -Descending\n"
        "    $bySource = $records | Group-Object -Property Source | "
        "    Select-Object Name,Count | Sort-Object Count -Descending | Select-Object -First 10\n"
        "    $appFailures = $records | Where-Object { $_.EventType -eq 'Application Failure' } | "
        "    Group-Object -Property Source | Select-Object Name,Count | Sort-Object Count -Descending\n"
        "    $updateFailures = $records | Where-Object { $_.EventType -eq 'Update Failure' } | "
        "    Group-Object -Property Source | Select-Object Name,Count | Sort-Object Count -Descending\n"
        "    $result = @{ total = $total; by_type = @(); by_source = @(); "
        "    app_failures = @(); update_failures = @() }\n"
        "    foreach ($t in $byType) { $result.by_type += @{ name = $t.Name; count = $t.Count } }\n"
        "    foreach ($s in $bySource) { $result.by_source += @{ name = $s.Name; count = $s.Count } }\n"
        "    foreach ($a in $appFailures) { $result.app_failures += @{ name = $a.Name; count = $a.Count } }\n"
        "    foreach ($u in $updateFailures) { $result.update_failures += @{ name = $u.Name; count = $u.Count } }\n"
        "    ConvertTo-Json $result -Compress\n"
        "} else {\n"
        "    ConvertTo-Json @{ total = 0; by_type = @(); by_source = @(); "
        "    app_failures = @(); update_failures = @() } -Compress\n"
        "}"
    )
    raw, error = run_powershell(script)
    if error or raw is None:
        return None

    item = raw if isinstance(raw, dict) else {}
    return {
        "total_records": item.get("total", 0),
        "by_type": item.get("by_type", []),
        "by_source": item.get("by_source", []),
        "app_failures": item.get("app_failures", []),
        "update_failures": item.get("update_failures", []),
    }


def collect_reliability() -> list[DiagnosticResult]:
    """Collect reliability and crash-history diagnostics.

    Uses a single WMI query to fetch all records, then derives
    three result types from the cached data.
    """
    results: list[DiagnosticResult] = []

    if platform.system() != "Windows":
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_summary",
            category=DiagnosticCategory.RELIABILITY,
            status=DiagnosticStatus.NOT_SUPPORTED,
            title="Reliability summary",
            summary="Reliability diagnostics are not supported on this platform.",
            source="platform_check",
        ))
        return results

    # Single WMI query for all reliability data
    data = _collect_all_reliability_records()
    if data is None:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_summary",
            category=DiagnosticCategory.RELIABILITY,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Reliability summary",
            summary="Reliability data could not be collected.",
            source="Win32_ReliabilityRecord",
        ))
        return results

    # Reliability summary (derived from cached data)
    total = data.get("total_records", 0)
    by_type = data.get("by_type", [])
    type_summary = ", ".join(
        f"{t['name']}({t['count']})" for t in by_type
    ) if by_type else "none"

    status = DiagnosticStatus.OK
    if total >= RELIABILITY_CRASH_WARN_THRESHOLD:
        status = DiagnosticStatus.WARNING

    results.append(DiagnosticResult(
        diagnostic_id=f"{_DIAG_ID}_summary",
        category=DiagnosticCategory.RELIABILITY,
        status=status,
        title="Reliability summary",
        summary=f"{total} reliability events in last {RELIABILITY_LOOKBACK_DAYS} days. Types: {type_summary}",
        evidence=data,
        source="Win32_ReliabilityRecord",
        limitations=[f"Bounded to {RELIABILITY_MAX_EVENTS} events, last {RELIABILITY_LOOKBACK_DAYS} days."],
    ))

    # Application failures (derived from same query)
    app_failures = data.get("app_failures", [])
    total_failures = sum(f.get("count", 0) for f in app_failures)
    top_apps = [f"{f['name']}({f['count']})" for f in app_failures[:3]]
    apps_summary = ", ".join(top_apps) if top_apps else "none"

    status = DiagnosticStatus.WARNING if total_failures >= RELIABILITY_CRASH_WARN_THRESHOLD else DiagnosticStatus.OK
    results.append(DiagnosticResult(
        diagnostic_id=f"{_DIAG_ID}_app_failures",
        category=DiagnosticCategory.RELIABILITY,
        status=status,
        title="Application failures",
        summary=f"{total_failures} application failure(s) in last {RELIABILITY_LOOKBACK_DAYS} days. Top: {apps_summary}",
        evidence={"failures": app_failures},
        source="Win32_ReliabilityRecord",
    ))

    # Windows Update failures (derived from same query)
    update_failures = data.get("update_failures", [])
    total_updates = sum(f.get("count", 0) for f in update_failures)
    top_updates = [f"{f['name']}({f['count']})" for f in update_failures[:3]]
    updates_summary = ", ".join(top_updates) if top_updates else "none"

    status = DiagnosticStatus.WARNING if total_updates > 0 else DiagnosticStatus.OK
    results.append(DiagnosticResult(
        diagnostic_id=f"{_DIAG_ID}_update_failures",
        category=DiagnosticCategory.RELIABILITY,
        status=status,
        title="Windows Update failures",
        summary=f"{total_updates} update failure(s) in last {RELIABILITY_LOOKBACK_DAYS} days. Sources: {updates_summary}",
        evidence={"failures": update_failures},
        source="Win32_ReliabilityRecord",
    ))

    return results
