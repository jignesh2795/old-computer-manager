"""Analyzer orchestrator -- runs all analyzers against a discovery run."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.analyzers import (
    battery_analyzer,
    process_analyzer,
    service_analyzer,
    startup_analyzer,
    storage_analyzer,
    task_analyzer,
)
from app.analyzers.finding import Finding
from app.database.sqlite import SnapshotStore

# All analyzer modules, in execution order.
Analyzers = [
    battery_analyzer,
    storage_analyzer,
    startup_analyzer,
    process_analyzer,
    service_analyzer,
    task_analyzer,
]


def run_analyzers(snapshots: dict[str, Any]) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Execute all analyzers and return (findings, errors).

    Each analyzer is executed in isolation.  If one analyzer raises an
    exception, it is recorded as an error and does not prevent the others
    from running.

    Returns:
        findings: All Finding objects produced by successful analyzers.
        errors: List of dicts describing analyzer failures, each with keys
                'analyzer', 'error_type', 'error_message'.
    """
    findings: list[Finding] = []
    errors: list[dict[str, Any]] = []

    for analyzer in Analyzers:
        try:
            results = analyzer.analyze(snapshots)
            findings.extend(results)
        except Exception as exc:
            errors.append(
                {
                    "analyzer": analyzer.name,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                }
            )

    return findings, errors


def save_findings(
    conn: sqlite3.Connection,
    run_id: int,
    findings: list[Finding],
    errors: list[dict[str, Any]],
) -> None:
    """Persist findings and analyzer errors to the database."""
    for finding in findings:
        conn.execute(
            "INSERT INTO findings("
            "  run_id, analyzer, severity, title, message,"
            "  evidence_json, recommendation"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                finding.analyzer,
                finding.severity,
                finding.title,
                finding.message,
                json.dumps(finding.evidence, default=str, sort_keys=True),
                finding.recommendation,
            ),
        )

    for error in errors:
        conn.execute(
            "INSERT INTO findings("
            "  run_id, analyzer, severity, title, message,"
            "  evidence_json, recommendation"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                error["analyzer"],
                "info",
                f"Analyzer error: {error['analyzer']}",
                (
                    f"The {error['analyzer']} analyzer failed with "
                    f"{error['error_type']}: {error['error_message']}"
                ),
                json.dumps(error, sort_keys=True),
                None,
            ),
        )

    # Set analysis_status: 'completed' if no errors, 'partial' if some errors
    if errors:
        analysis_status = "partial"
    else:
        analysis_status = "completed"
    conn.execute(
        "UPDATE discovery_runs SET analysis_status = ? WHERE id = ?",
        (analysis_status, run_id),
    )

    conn.commit()


def analyze_latest_run(store: SnapshotStore) -> dict[str, Any]:
    """Analyze the latest completed discovery run.

    Returns a summary dict with keys: run_id, findings_count, errors_count,
    findings, errors.
    """
    run = store.get_latest_completed_run()
    if run is None:
        return {
            "run_id": None,
            "findings_count": 0,
            "errors_count": 0,
            "findings": [],
            "errors": [],
            "message": "No completed discovery run found.",
        }

    run_id = run["id"]
    try:
        snapshots = store.load_snapshots(run_id)
        findings, errors = run_analyzers(snapshots)

        with store._connect() as connection:
            save_findings(connection, run_id, findings, errors)
    except Exception as exc:
        store.set_analysis_status(run_id, "failed")
        return {
            "run_id": run_id,
            "findings_count": 0,
            "errors_count": 1,
            "findings": [],
            "errors": [{"analyzer": "analysis", "error_type": type(exc).__name__, "error_message": str(exc)}],
            "message": f"Analysis failed: {exc}",
        }

    return {
        "run_id": run_id,
        "findings_count": len(findings),
        "errors_count": len(errors),
        "findings": [
            {
                "analyzer": f.analyzer,
                "severity": f.severity,
                "title": f.title,
                "message": f.message,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
        "errors": errors,
    }
