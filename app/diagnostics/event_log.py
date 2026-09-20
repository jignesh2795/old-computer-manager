"""Read-only Windows Event Log diagnostics.

Bounded collection from Windows Event Log with crash/error grouping
and recurring-event detection. Does NOT dump raw event logs.
Does NOT modify event log settings or clear logs.
"""

from __future__ import annotations

import platform
from collections import Counter
from typing import Any

from app.diagnostics._powershell import run_powershell
from app.diagnostics.constants import (
    EVENT_LOG_ERROR_WARN_THRESHOLD,
    EVENT_LOG_LOOKBACK_DAYS,
    EVENT_LOG_MAX_EVENTS,
    EVENT_LOG_RECURRING_THRESHOLD,
)
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

_DIAG_ID = "event_log"


def _collect_system_errors() -> dict[str, Any] | None:
    """Collect bounded system error events from the last N days.

    Groups by source and counts occurrences. No raw event flood.
    """
    if platform.system() != "Windows":
        return None

    script = (
        f"$cutoff = (Get-Date).AddDays(-{EVENT_LOG_LOOKBACK_DAYS})\n"
        f"$events = Get-WinEvent -FilterHashtable @{{LogName='System'; Level=1,2; StartTime=$cutoff}} "
        f"-MaxEvents {EVENT_LOG_MAX_EVENTS} -ErrorAction SilentlyContinue\n"
        "if ($events) {\n"
        "    $grouped = $events | Group-Object -Property ProviderName | "
        "    Select-Object Name,Count | Sort-Object Count -Descending | Select-Object -First 20\n"
        "    $total = ($events | Measure-Object).Count\n"
        "    $result = @{ total = $total; sources = @() }\n"
        "    foreach ($g in $grouped) {\n"
        "        $result.sources += @{ name = $g.Name; count = $g.Count }\n"
        "    }\n"
        "    ConvertTo-Json $result -Compress\n"
        "} else {\n"
        "    ConvertTo-Json @{ total = 0; sources = @() } -Compress\n"
        "}"
    )
    raw, error = run_powershell(script)
    if error or raw is None:
        return None

    item = raw if isinstance(raw, dict) else {}
    return {
        "total_errors": item.get("total", 0),
        "sources": item.get("sources", []),
    }


def _collect_application_crashes() -> dict[str, Any] | None:
    """Collect bounded application crash events from the last N days.

    Groups by application name. No raw event details.
    """
    if platform.system() != "Windows":
        return None

    script = (
        f"$cutoff = (Get-Date).AddDays(-{EVENT_LOG_LOOKBACK_DAYS})\n"
        f"$events = Get-WinEvent -FilterHashtable @{{LogName='Application'; Level=2; StartTime=$cutoff}} "
        f"-MaxEvents {EVENT_LOG_MAX_EVENTS} -ErrorAction SilentlyContinue\n"
        "if ($events) {\n"
        "    $grouped = $events | Group-Object -Property ProviderName | "
        "    Select-Object Name,Count | Sort-Object Count -Descending | Select-Object -First 20\n"
        "    $total = ($events | Measure-Object).Count\n"
        "    $result = @{ total = $total; sources = @() }\n"
        "    foreach ($g in $grouped) {\n"
        "        $result.sources += @{ name = $g.Name; count = $g.Count }\n"
        "    }\n"
        "    ConvertTo-Json $result -Compress\n"
        "} else {\n"
        "    ConvertTo-Json @{ total = 0; sources = @() } -Compress\n"
        "}"
    )
    raw, error = run_powershell(script)
    if error or raw is None:
        return None

    item = raw if isinstance(raw, dict) else {}
    return {
        "total_crashes": item.get("total", 0),
        "sources": item.get("sources", []),
    }


def _detect_recurring_errors(
    system_errors: dict[str, Any] | None,
    app_crashes: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Detect sources that appear frequently across error categories.

    A source appearing in both system and application errors, or with
    high count in either, is flagged as recurring.
    """
    recurring: list[dict[str, Any]] = []

    system_sources: dict[str, int] = {}
    if system_errors:
        for src in system_errors.get("sources", []):
            name = src.get("name", "")
            count = src.get("count", 0)
            if name and count >= EVENT_LOG_RECURRING_THRESHOLD:
                system_sources[name] = count

    app_sources: dict[str, int] = {}
    if app_crashes:
        for src in app_crashes.get("sources", []):
            name = src.get("name", "")
            count = src.get("count", 0)
            if name and count >= EVENT_LOG_RECURRING_THRESHOLD:
                app_sources[name] = count

    # Sources appearing in both system and application errors
    both = set(system_sources.keys()) & set(app_sources.keys())
    for name in sorted(both):
        recurring.append({
            "source": name,
            "system_count": system_sources[name],
            "application_count": app_sources[name],
            "reason": "appears in both system and application errors",
        })

    # High-count sources in system errors only
    for name, count in sorted(system_sources.items(), key=lambda x: -x[1]):
        if name not in both and count >= EVENT_LOG_RECURRING_THRESHOLD * 2:
            recurring.append({
                "source": name,
                "system_count": count,
                "application_count": 0,
                "reason": "frequent system error",
            })

    # High-count sources in application crashes only
    for name, count in sorted(app_sources.items(), key=lambda x: -x[1]):
        if name not in both and count >= EVENT_LOG_RECURRING_THRESHOLD * 2:
            recurring.append({
                "source": name,
                "system_count": 0,
                "application_count": count,
                "reason": "frequent application crash",
            })

    return recurring[:10]


def collect_event_log() -> list[DiagnosticResult]:
    """Collect bounded event log diagnostics with grouping and recurring detection."""
    results: list[DiagnosticResult] = []

    if platform.system() != "Windows":
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_system_errors",
            category=DiagnosticCategory.EVENT_LOG,
            status=DiagnosticStatus.NOT_SUPPORTED,
            title="System error events",
            summary="Event log diagnostics are not supported on this platform.",
            source="platform_check",
        ))
        return results

    # System errors
    system_errors = _collect_system_errors()
    if system_errors is not None:
        total = system_errors.get("total_errors", 0)
        top_sources = system_errors.get("sources", [])[:5]
        source_summary = ", ".join(
            f"{s['name']}({s['count']})" for s in top_sources
        ) if top_sources else "none"

        status = DiagnosticStatus.WARNING if total >= EVENT_LOG_ERROR_WARN_THRESHOLD else DiagnosticStatus.OK
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_system_errors",
            category=DiagnosticCategory.EVENT_LOG,
            status=status,
            title="System error events",
            summary=f"{total} error/warning events in last {EVENT_LOG_LOOKBACK_DAYS} days. Top sources: {source_summary}",
            evidence=system_errors,
            source="WinEvent/System",
            limitations=[f"Bounded to {EVENT_LOG_MAX_EVENTS} events, last {EVENT_LOG_LOOKBACK_DAYS} days."],
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_system_errors",
            category=DiagnosticCategory.EVENT_LOG,
            status=DiagnosticStatus.UNAVAILABLE,
            title="System error events",
            summary="System error events could not be collected.",
            source="WinEvent/System",
        ))

    # Application crashes
    app_crashes = _collect_application_crashes()
    if app_crashes is not None:
        total = app_crashes.get("total_crashes", 0)
        top_sources = app_crashes.get("sources", [])[:5]
        source_summary = ", ".join(
            f"{s['name']}({s['count']})" for s in top_sources
        ) if top_sources else "none"

        status = DiagnosticStatus.WARNING if total >= EVENT_LOG_RECURRING_THRESHOLD else DiagnosticStatus.OK
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_app_crashes",
            category=DiagnosticCategory.EVENT_LOG,
            status=status,
            title="Application crash events",
            summary=f"{total} application crashes in last {EVENT_LOG_LOOKBACK_DAYS} days. Top sources: {source_summary}",
            evidence=app_crashes,
            source="WinEvent/Application",
            limitations=[f"Bounded to {EVENT_LOG_MAX_EVENTS} events, last {EVENT_LOG_LOOKBACK_DAYS} days."],
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_app_crashes",
            category=DiagnosticCategory.EVENT_LOG,
            status=DiagnosticStatus.UNAVAILABLE,
            title="Application crash events",
            summary="Application crash events could not be collected.",
            source="WinEvent/Application",
        ))

    # Recurring event detection
    recurring = _detect_recurring_errors(system_errors, app_crashes)
    if recurring:
        summary_parts = [f"{r['source']}({r['reason']})" for r in recurring[:3]]
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_recurring",
            category=DiagnosticCategory.EVENT_LOG,
            status=DiagnosticStatus.WARNING,
            title="Recurring error sources",
            summary=f"{len(recurring)} recurring error source(s) detected: {'; '.join(summary_parts)}",
            evidence={"recurring_sources": recurring},
            source="event_log_analysis",
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_recurring",
            category=DiagnosticCategory.EVENT_LOG,
            status=DiagnosticStatus.OK,
            title="Recurring error sources",
            summary="No recurring error sources detected.",
            source="event_log_analysis",
        ))

    return results
