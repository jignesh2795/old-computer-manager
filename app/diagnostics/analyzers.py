"""Diagnostic analyzers that convert diagnostic observations into findings.

Each analyzer takes a list of DiagnosticResults and produces Finding objects
that integrate with the existing analysis framework.
"""

from __future__ import annotations

from typing import Any

from app.analyzers.finding import Finding
from app.diagnostics.constants import (
    CPU_HIGH_PERCENT,
    CPU_TEMP_CRITICAL,
    CPU_TEMP_WARNING,
    DISK_TEMP_CRITICAL,
    DISK_TEMP_WARNING,
    MEMORY_HIGH_PERCENT,
)
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

name = "diagnostics"


def _evidence_str(result: DiagnosticResult) -> str:
    """Create a concise evidence string from a diagnostic result."""
    parts = [f"source={result.source}"]
    for key, val in result.evidence.items():
        if val is not None and val != "" and val != "Unknown":
            parts.append(f"{key}={val}")
    return ", ".join(parts[:6])


def analyze_diagnostics(results: list[DiagnosticResult]) -> list[Finding]:
    """Convert diagnostic results into conservative evidence-based findings."""
    findings: list[Finding] = []

    for result in results:
        if result.status == DiagnosticStatus.OK:
            continue

        if result.status == DiagnosticStatus.FAILED:
            findings.append(Finding(
                analyzer=name,
                severity="warning",
                title=f"Diagnostic failed: {result.title}",
                message=result.summary,
                evidence={"diagnostic_id": result.diagnostic_id, "errors": result.errors},
            ))
            continue

        if result.status == DiagnosticStatus.NOT_SUPPORTED:
            continue

        if result.status == DiagnosticStatus.UNAVAILABLE:
            findings.append(Finding(
                analyzer=name,
                severity="info",
                title=f"Data unavailable: {result.title}",
                message=result.summary,
                evidence={"diagnostic_id": result.diagnostic_id, "limitations": result.limitations},
            ))
            continue

        if result.status == DiagnosticStatus.WARNING:
            findings.append(Finding(
                analyzer=name,
                severity="warning",
                title=f"Observation: {result.title}",
                message=result.summary,
                evidence=result.evidence,
            ))
            continue

        if result.status == DiagnosticStatus.CRITICAL:
            findings.append(Finding(
                analyzer=name,
                severity="critical",
                title=f"Critical observation: {result.title}",
                message=result.summary,
                evidence=result.evidence,
            ))
            continue

    return findings
