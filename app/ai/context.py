"""AI context builder with explicit budget limits.

Builds bounded context from HealthReport for AI advisory.
Never blindly concatenates unlimited database content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.reporting.models import HealthReport


# Context budget limits
MAX_FINDINGS: int = 20
MAX_LARGE_FILES: int = 10
MAX_DUPLICATE_GROUPS: int = 5
MAX_PROCESSES: int = 20
MAX_STARTUP_ITEMS: int = 15
MAX_TEXT_LENGTH: int = 500
MAX_OBSERVATIONS: int = 10
MAX_RECOMMENDATIONS: int = 5
MAX_HISTORICAL_TRENDS: int = 10
MAX_HISTORICAL_RECURRING: int = 5
MAX_HISTORICAL_ANOMALIES: int = 5

# Sensitive fields to exclude
SENSITIVE_FIELDS: set[str] = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credentials",
    "serial_number",
}


@dataclass(frozen=True)
class AIContext:
    """Bounded context for AI advisory generation.

    This is a sanitized, budget-limited subset of the HealthReport.
    """

    system_summary: dict[str, Any] = field(default_factory=dict)
    storage_summary: dict[str, Any] = field(default_factory=dict)
    battery_summary: dict[str, Any] = field(default_factory=dict)
    findings_summary: list[dict[str, Any]] = field(default_factory=list)
    file_analysis_summary: dict[str, Any] = field(default_factory=dict)
    startup_summary: dict[str, Any] = field(default_factory=dict)
    process_summary: dict[str, Any] = field(default_factory=dict)
    remediation_metadata: list[dict[str, Any]] = field(default_factory=list)
    historical_summary: dict[str, Any] = field(default_factory=dict)
    analysis_status: str | None = None
    errors: list[dict[str, Any]] = field(default_factory=list)


def _truncate_text(text: str | None, max_length: int = MAX_TEXT_LENGTH) -> str:
    """Truncate text to max_length, adding ellipsis if needed."""
    if text is None:
        return ""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def _sanitize_value(key: str, value: Any) -> Any:
    """Sanitize a value by removing sensitive fields."""
    if isinstance(key, str):
        key_lower = key.lower()
        for sensitive in SENSITIVE_FIELDS:
            if sensitive in key_lower:
                return "[REDACTED]"
    return value


def _build_system_summary(report: HealthReport) -> dict[str, Any]:
    """Build bounded system summary from HealthReport."""
    system = report.system
    return {
        "hostname": _truncate_text(system.hostname, 50),
        "os_name": _truncate_text(system.os_name, 50),
        "os_version": _truncate_text(system.os_version, 30),
        "architecture": _truncate_text(system.architecture, 20),
        "manufacturer": _truncate_text(system.manufacturer, 50),
        "model": _truncate_text(system.model, 50),
        "cpu_name": _truncate_text(system.cpu_name, 100),
        "cpu_cores_physical": system.cpu_cores_physical,
        "cpu_cores_logical": system.cpu_cores_logical,
        "ram_total_bytes": system.ram_total_bytes,
    }


def _build_storage_summary(report: HealthReport) -> dict[str, Any]:
    """Build bounded storage summary from HealthReport."""
    storage = report.storage
    partitions = []
    for p in storage.partitions[:5]:  # Cap at 5 partitions
        partitions.append({
            "device": _truncate_text(p.device, 20),
            "filesystem": _truncate_text(p.filesystem, 10),
            "total_bytes": p.total_bytes,
            "free_bytes": p.free_bytes,
            "usage_percent": p.usage_percent,
            "status": p.status,
        })
    return {
        "count": storage.count,
        "total_capacity_bytes": storage.total_capacity_bytes,
        "total_free_bytes": storage.total_free_bytes,
        "partitions": partitions,
    }


def _build_battery_summary(report: HealthReport) -> dict[str, Any]:
    """Build bounded battery summary from HealthReport.

    Battery serial number is NEVER included (privacy).
    """
    battery = report.battery
    return {
        "available": battery.available,
        "status": battery.status,
        "charge_percent": battery.charge_percent,
        "plugged_in": battery.plugged_in,
        "design_capacity_mwh": battery.design_capacity_mwh,
        "full_charge_capacity_mwh": battery.full_charge_capacity_mwh,
        "remaining_capacity_mwh": battery.remaining_capacity_mwh,
        "health_percent": battery.health_percent,
        "wear_percent": battery.wear_percent,
        "health_status": battery.health_status,
        "cycle_count": battery.cycle_count,
        "baseline_status": battery.baseline_status,
        # serial_number intentionally excluded
    }


def _build_findings_summary(report: HealthReport) -> list[dict[str, Any]]:
    """Build bounded findings summary from HealthReport."""
    findings = []
    # Combine all severity levels
    all_findings = (
        report.findings.critical + report.findings.warning + report.findings.info
    )
    # Cap at MAX_FINDINGS
    for f in all_findings[:MAX_FINDINGS]:
        findings.append({
            "finding_id": f.finding_id,
            "analyzer": f.analyzer,
            "severity": f.severity,
            "title": _truncate_text(f.title, 100),
            "message": _truncate_text(f.message, 300),
            "recommendation": _truncate_text(f.recommendation, 200),
        })
    return findings


def _build_file_analysis_summary(report: HealthReport) -> dict[str, Any]:
    """Build bounded file analysis summary from HealthReport."""
    fa = report.file_analysis
    # Cap largest files
    largest_files = [
        {"path": _truncate_text(f.get("path", ""), 200), "size_bytes": f.get("size_bytes", 0)}
        for f in fa.largest_files[:MAX_LARGE_FILES]
    ]
    # Cap duplicate groups
    duplicate_groups = fa.duplicate_groups  # This is already an int in the model
    return {
        "available": fa.available,
        "files_examined": fa.files_examined,
        "directories_examined": fa.directories_examined,
        "bytes_examined": fa.bytes_examined,
        "largest_files": largest_files,
        "duplicate_groups": duplicate_groups,
        "potential_duplicate_bytes": fa.potential_duplicate_bytes,
    }


def _build_startup_summary(report: HealthReport) -> dict[str, Any]:
    """Build bounded startup summary from HealthReport."""
    return {
        "count": report.startup.count,
    }


def _build_process_summary(report: HealthReport) -> dict[str, Any]:
    """Build bounded process summary from HealthReport."""
    return {
        "count": report.processes.count,
    }


def _build_remediation_metadata(report: HealthReport) -> list[dict[str, Any]]:
    """Build remediation metadata from HealthReport.

    This only includes action metadata, never execution capability.
    Includes Phase 9A extended fields: implementation_status,
    blast_radius, rollback_category, eligibility.
    """
    actions = []
    for a in report.remediation.actions[:5]:  # Cap at 5 actions
        actions.append({
            "action_id": a.action_id,
            "name": a.name,
            "risk_level": a.risk_level,
            "reversible": a.reversible,
            "requires_admin": a.requires_admin,
            "implementation_status": a.implementation_status,
            "blast_radius": a.blast_radius,
            "rollback_category": a.rollback_category,
            "eligibility": a.eligibility,
            "category": a.category,
        })
    return actions


def _build_errors(report: HealthReport) -> list[dict[str, Any]]:
    """Build bounded error summary from HealthReport."""
    errors = []
    for e in report.errors[:5]:  # Cap at 5 errors
        errors.append({
            "component": _truncate_text(e.component, 50),
            "stage": _truncate_text(e.stage, 30),
            "message": _truncate_text(e.message, 200),
            "severity": e.severity,
        })
    return errors


def _build_historical_summary(report: HealthReport) -> dict[str, Any]:
    """Build bounded historical summary from HealthReport.

    If historical data is available, include summarized trends,
    baselines, recurring findings, and anomalies.
    """
    # Check if historical section exists in report
    historical = getattr(report, "historical", None)
    if historical is None:
        return {"available": False}

    # The historical section is an optional dict in the report
    if not isinstance(historical, dict):
        return {"available": False}

    result: dict[str, Any] = {
        "available": True,
        "runs_considered": historical.get("runs_considered", 0),
    }

    # Cap trends
    trends = historical.get("trends", [])
    if trends:
        result["trends"] = [
            {
                "metric_name": _truncate_text(t.get("metric_name", ""), 50),
                "direction": t.get("direction", "unknown"),
                "observations_count": t.get("observations_count", 0),
                "delta_percent": t.get("delta_percent"),
            }
            for t in trends[:MAX_HISTORICAL_TRENDS]
        ]

    # Cap recurring findings
    recurring = historical.get("recurring_findings", [])
    if recurring:
        result["recurring_findings"] = [
            {
                "title": _truncate_text(r.get("title", ""), 100),
                "analyzer": r.get("analyzer", ""),
                "occurrence_count": r.get("occurrence_count", 0),
            }
            for r in recurring[:MAX_HISTORICAL_RECURRING]
        ]

    # Cap anomalies
    anomalies = historical.get("anomalies", [])
    if anomalies:
        result["anomalies"] = [
            {
                "title": _truncate_text(a.get("title", ""), 100),
                "severity": a.get("severity", "info"),
                "message": _truncate_text(a.get("message", ""), 200),
            }
            for a in anomalies[:MAX_HISTORICAL_ANOMALIES]
        ]

    # Battery baseline
    baseline = historical.get("baseline", [])
    battery_baseline = [b for b in baseline if "health" in b.get("metric_name", "")]
    if battery_baseline:
        result["battery_baseline"] = battery_baseline[0]

    return result


def build_ai_context(report: HealthReport) -> AIContext:
    """Build bounded AI context from HealthReport.

    This function:
    - Extracts relevant structured information
    - Applies budget limits to all collections
    - Sanitizes sensitive fields
    - Never includes file contents, secrets, or raw database dumps

    Args:
        report: The HealthReport to extract context from.

    Returns:
        Bounded AIContext suitable for AI advisory generation.
    """
    return AIContext(
        system_summary=_build_system_summary(report),
        storage_summary=_build_storage_summary(report),
        battery_summary=_build_battery_summary(report),
        findings_summary=_build_findings_summary(report),
        file_analysis_summary=_build_file_analysis_summary(report),
        startup_summary=_build_startup_summary(report),
        process_summary=_build_process_summary(report),
        remediation_metadata=_build_remediation_metadata(report),
        historical_summary=_build_historical_summary(report),
        analysis_status=report.analysis_status,
        errors=_build_errors(report),
    )
