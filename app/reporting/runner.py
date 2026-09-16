"""Orchestrate report generation from existing data."""

from __future__ import annotations

from app.database.sqlite import SnapshotStore
from app.reporting.builder import build_health_report
from app.reporting.json_export import report_to_dict, report_to_json
from app.reporting.models import HealthReport


def generate_report(store: SnapshotStore | None = None) -> HealthReport:
    """Build the unified health report."""
    return build_health_report(store)


def generate_json(report: HealthReport, *, indent: int = 2) -> str:
    """Serialize the report to JSON."""
    return report_to_json(report, indent=indent)


def generate_human(report: HealthReport) -> str:
    """Format the report for human reading."""
    from app.reporting.formatter import format_report

    return format_report(report)
