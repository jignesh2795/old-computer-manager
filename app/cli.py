"""Command-line entry point for discovery, analysis, and remediation."""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sys
import tempfile
from pathlib import Path

from app.database.sqlite import SnapshotStore


def cmd_discover(args: argparse.Namespace) -> int:
    """Run a full discovery scan."""
    from app.discovery import run

    print("Old Computer Manager v0.9.1-alpha")
    print("Read-only discovery mode")
    print(f"Platform: {platform.platform()}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Computer name: {socket.gethostname()}")
    print("Collecting baseline information...\n")

    results, summary = run()
    print(json.dumps(results, indent=2, default=str))

    print("\n--- Discovery Summary ---")
    print(json.dumps(summary, indent=2, default=str))

    print("\nBaseline saved to data/computer.db")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyze the latest completed discovery run."""
    from app.analyzers.runner import analyze_latest_run

    print("Old Computer Manager v0.9.1-alpha")
    print("Read-only analysis mode\n")

    store = SnapshotStore()
    result = analyze_latest_run(store)

    if result["run_id"] is None:
        print(result["message"])
        return 0

    print(f"Analyzing discovery run {result['run_id']}...")
    print(f"Findings: {result['findings_count']}")
    print(f"Analyzer errors: {result['errors_count']}\n")

    print(json.dumps(result, indent=2, default=str))

    print("\nFindings saved to data/computer.db")
    return 0


def cmd_actions(args: argparse.Namespace) -> int:
    """List registered remediation actions."""
    from app.remediation.registry import create_default_registry

    print("Old Computer Manager v0.9.1-alpha")
    print("Remediation actions\n")

    registry = create_default_registry()
    actions = registry.list_actions()

    if not actions:
        print("No actions registered.")
        return 0

    print(f"Registered actions: {len(actions)}\n")

    for action in actions:
        print(f"  [{action.action_id}]")
        print(f"    Name:        {action.name}")
        print(f"    Risk:        {action.risk_level.value}")
        print(f"    Target:      {action.target}")
        print(f"    Admin:       {'yes' if action.requires_admin else 'no'}")
        print(f"    Reversible:  {'yes' if action.reversible else 'no'}")
        print(f"    Idempotent:  {'yes' if action.idempotent else 'no'}")
        print(f"    Description: {action.description}")
        print()

    return 0


def cmd_actions_preview(args: argparse.Namespace) -> int:
    """Preview what an action would do without executing."""
    from app.remediation.registry import create_default_registry
    from app.remediation.preview import preview_action
    import json as json_mod

    print("Old Computer Manager v0.9.1-alpha")
    print(f"Action preview: {args.action_id}\n")

    registry = create_default_registry()

    if not registry.is_registered(args.action_id):
        print(f"Error: Action '{args.action_id}' is not registered.")
        print("Use 'actions' to list available actions.")
        return 1

    action = registry.get(args.action_id)

    # Build action with parameters
    params = {}
    if args.age_days is not None:
        params["age_days"] = args.age_days

    from app.remediation.action import RemediationAction, RiskLevel
    action_with_params = RemediationAction(
        action_id=action.action_id,
        name=action.name,
        description=action.description,
        risk_level=action.risk_level,
        target=action.target,
        reason=action.reason,
        requires_admin=action.requires_admin,
        reversible=action.reversible,
        preview=action.preview,
        parameters=params,
        idempotent=action.idempotent,
    )

    preview = preview_action(action_with_params)

    print(f"Action:        {preview.name}")
    print(f"Risk:          {preview.risk_level}")
    print(f"Target:        {preview.target}")
    print(f"Reversible:    {'yes' if preview.reversible else 'no'}")
    print(f"Would change:  {preview.would_change}")
    print()

    if preview.quarantine_plan is not None:
        plan = preview.quarantine_plan
        print(f"Source dir:    {plan.source_dir}")
        print(f"Quarantine:    {plan.quarantine_dir}")
        print(f"Age threshold: {plan.age_threshold_days} days")
        print(f"Files examined: {plan.files_examined}")
        print(f"Files eligible: {plan.files_eligible}")
        print(f"Total size:    {plan.total_size_bytes:,} bytes")
        print()

        if plan.warnings:
            print("Warnings:")
            for w in plan.warnings:
                print(f"  - {w}")
            print()

        if plan.eligible_files:
            print(f"Eligible files (showing {len(plan.eligible_files)}):")
            for f in plan.eligible_files[:50]:
                print(f"  {f.path}  ({f.size:,} bytes, mtime: {f.mtime_iso})")
            if len(plan.eligible_files) > 50:
                print(f"  ... and {len(plan.eligible_files) - 50} more")
            print()

    print("Caveats:")
    for note in preview.what_is_not_guaranteed:
        print(f"  - {note}")

    return 0


def cmd_actions_execute(args: argparse.Namespace) -> int:
    """Execute a registered action with explicit confirmation."""
    from app.remediation.registry import create_default_registry
    from app.remediation.validation import validate_action
    from app.remediation.confirmation import confirm_action
    from app.remediation.executor import QuarantineExecutor
    from app.remediation.quarantine_store import QuarantineStore
    from app.remediation.audit import AuditStore
    import json as json_mod

    print("Old Computer Manager v0.9.1-alpha")
    print(f"Execute action: {args.action_id}\n")

    registry = create_default_registry()

    if not registry.is_registered(args.action_id):
        print(f"Error: Action '{args.action_id}' is not registered.")
        return 1

    action = registry.get(args.action_id)

    # Build action with parameters
    params = {}
    if args.age_days is not None:
        params["age_days"] = args.age_days

    from app.remediation.action import RemediationAction, RiskLevel
    action_with_params = RemediationAction(
        action_id=action.action_id,
        name=action.name,
        description=action.description,
        risk_level=action.risk_level,
        target=action.target,
        reason=action.reason,
        requires_admin=action.requires_admin,
        reversible=action.reversible,
        preview=action.preview,
        parameters=params,
        idempotent=action.idempotent,
    )

    # Validate
    validation = validate_action(action_with_params, registry)
    if not validation.valid:
        print("Validation FAILED:")
        for err in validation.errors:
            print(f"  - {err}")
        return 1

    print("Validation: PASSED")

    # Create confirmation token
    token = confirm_action(action_with_params)
    print(f"Confirmation token created: {token.action_id}")
    print()

    # Execute
    db_path = Path("data/computer.db")
    quarantine_store = QuarantineStore(db_path)
    audit_store = AuditStore(db_path)

    executor = QuarantineExecutor(quarantine_store)
    result = executor.execute(
        action_with_params, token, validation, registry, audit_store
    )

    print(f"Result: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"Message: {result.message}")
    print()

    if result.details:
        print("Details:")
        for key, value in result.details.items():
            if key == "failure_reasons":
                if value:
                    print(f"  {key}:")
                    for path, reason in value.items():
                        print(f"    {path}: {reason}")
            else:
                print(f"  {key}: {value}")

    return 0 if result.success else 1


def cmd_actions_rollback(args: argparse.Namespace) -> int:
    """Restore a quarantined file to its original location."""
    from app.remediation.quarantine_store import QuarantineStore
    from app.remediation.rollback import rollback_quarantine_file
    from app.remediation.audit import AuditStore, AuditStatus
    from app.database.sqlite import SnapshotStore

    print("Old Computer Manager v0.9.1-alpha")
    print(f"Rollback quarantine record: {args.record_id}\n")

    db_path = Path("data/computer.db")
    quarantine_store = QuarantineStore(db_path)

    record = quarantine_store.get_record(args.record_id)
    if record is None:
        print(f"Error: Quarantine record {args.record_id} not found.")
        return 1

    if record.restored:
        print(f"Record {args.record_id} was already restored.")
        return 1

    print(f"Original path:  {record.original_path}")
    print(f"Quarantine path: {record.quarantine_path}")
    print(f"Original size:   {record.original_size:,} bytes")
    print()

    success, message = rollback_quarantine_file(
        quarantine_store, args.record_id, overwrite=args.overwrite
    )

    print(f"Result: {'SUCCESS' if success else 'FAILED'}")
    print(f"Message: {message}")

    if success:
        # Update audit record
        audit_store = AuditStore(db_path)
        if record.audit_record_id:
            try:
                audit_store.update_status(
                    record.audit_record_id,
                    AuditStatus.ROLLED_BACK,
                    result_summary=f"Rolled back quarantine record {args.record_id}",
                )
            except Exception:
                pass  # Audit update is best-effort

    return 0 if success else 1


def cmd_files_scan(args: argparse.Namespace) -> int:
    """Scan a directory and run file analysis."""
    from app.file_analysis.runner import run_file_analysis
    from app.database.sqlite import SnapshotStore

    print("Old Computer Manager v0.9.1-alpha")
    print(f"File scan: {args.path}\n")

    try:
        result = run_file_analysis(
            args.path,
            large_top_n=args.top_n,
            large_min_bytes=args.min_size,
        )
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1

    # Save to database
    store = SnapshotStore()
    scan_id = store.start_file_scan(result.scan_root)
    store.complete_file_scan(scan_id, {
        "files_examined": result.stats.files_examined,
        "directories_examined": result.stats.directories_examined,
        "bytes_examined": result.stats.bytes_examined,
        "files_skipped": result.stats.files_skipped,
        "inaccessible_items": result.stats.inaccessible_items,
        "symlinks_skipped": result.stats.symlinks_skipped,
        "excluded_items": result.stats.excluded_items,
        "elapsed_seconds": result.stats.elapsed_seconds,
        "error_count": len(result.stats.errors),
    })
    if result.large_files:
        store.save_file_scan_large_files(scan_id, [
            {"path": f.path, "size_bytes": f.size_bytes} for f in result.large_files
        ])
    if result.file_type_groups:
        store.save_file_scan_type_groups(scan_id, [
            {
                "extension": t.extension,
                "file_count": t.file_count,
                "total_size_bytes": t.total_size_bytes,
            }
            for t in result.file_type_groups
        ])
    if result.duplicate_groups:
        store.save_file_scan_duplicate_groups(scan_id, [
            {
                "group_id": d.group_id,
                "size_bytes": d.size_bytes,
                "match_type": d.match_type,
                "hash_value": d.hash_value,
                "paths": d.paths,
            }
            for d in result.duplicate_groups
        ])

    # Print results
    print(f"Scan root:    {result.scan_root}")
    print(f"Files:        {result.stats.files_examined:,}")
    print(f"Directories:  {result.stats.directories_examined:,}")
    print(f"Total size:   {_format_bytes(result.stats.bytes_examined)}")
    print(f"Skipped:      {result.stats.files_skipped} files, "
          f"{result.stats.symlinks_skipped} symlinks, "
          f"{result.stats.excluded_items} excluded")
    print(f"Inaccessible: {result.stats.inaccessible_items}")
    print(f"Errors:       {len(result.stats.errors)}")
    print(f"Runtime:      {result.stats.elapsed_seconds:.2f}s")
    print(f"Scan ID:      {scan_id}")

    if result.large_files:
        print(f"\nTop {len(result.large_files)} largest files:")
        for f in result.large_files[:20]:
            print(f"  {_format_bytes(f.size_bytes):>10s}  {f.path}")
        if len(result.large_files) > 20:
            print(f"  ... and {len(result.large_files) - 20} more")

    if result.directory_sizes:
        print(f"\nTop {min(10, len(result.directory_sizes))} largest directories:")
        for d in result.directory_sizes[:10]:
            print(f"  {_format_bytes(d.total_size_bytes):>10s}  ({d.file_count} files)  {d.path}")

    if result.file_type_groups:
        print(f"\nFile types (top 10):")
        for t in result.file_type_groups[:10]:
            print(f"  {t.extension:>15s}  {t.file_count:>6d} files  {_format_bytes(t.total_size_bytes)}")

    if result.duplicate_groups:
        total_dup_bytes = sum(g.size_bytes * (len(g.paths) - 1) for g in result.duplicate_groups)
        print(f"\nDuplicate groups: {len(result.duplicate_groups)} "
              f"({_format_bytes(total_dup_bytes)} potential savings)")
        for g in result.duplicate_groups[:5]:
            print(f"  Group {g.group_id}: {len(g.paths)} files, "
                  f"{_format_bytes(g.size_bytes)} each ({g.match_type})")
            for p in g.paths[:3]:
                print(f"    {p}")
            if len(g.paths) > 3:
                print(f"    ... and {len(g.paths) - 3} more")

    if result.stats.errors:
        print(f"\nErrors ({len(result.stats.errors)}):")
        for err in result.stats.errors[:10]:
            print(f"  {err}")

    print(f"\nResults saved to data/computer.db (scan {scan_id})")
    return 0


def cmd_files_large(args: argparse.Namespace) -> int:
    """Show large files from the latest scan or scan a directory."""
    from app.file_analysis.runner import run_file_analysis
    from app.database.sqlite import SnapshotStore

    print("Old Computer Manager v0.9.1-alpha")
    print("Large file analysis\n")

    # Use provided path or latest scan
    if args.path:
        try:
            result = run_file_analysis(
                args.path,
                large_top_n=args.top_n,
                large_min_bytes=args.min_size,
            )
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1
        large_files = result.large_files
        scan_root = result.scan_root
    else:
        store = SnapshotStore()
        latest = store.get_latest_file_scan()
        if latest is None:
            print("No file scan found. Run 'files scan <path>' first.")
            return 1
        scan_root = latest["scan_root"]
        large_files_raw = store.load_file_scan_large_files(latest["id"])
        large_files = [
            {"path": f["path"], "size_bytes": f["size_bytes"]}
            for f in large_files_raw
        ]

    print(f"Scan root: {scan_root}")
    print(f"Large files (>{_format_bytes(args.min_size)}):\n")

    if not large_files:
        print("No large files found.")
        return 0

    for i, f in enumerate(large_files[:args.top_n], 1):
        if isinstance(f, dict):
            print(f"  {i:>3d}. {_format_bytes(f['size_bytes']):>10s}  {f['path']}")
        else:
            print(f"  {i:>3d}. {_format_bytes(f.size_bytes):>10s}  {f.path}")

    return 0


def cmd_files_types(args: argparse.Namespace) -> int:
    """Show file type breakdown from the latest scan or scan a directory."""
    from app.file_analysis.runner import run_file_analysis
    from app.database.sqlite import SnapshotStore

    print("Old Computer Manager v0.9.1-alpha")
    print("File type analysis\n")

    if args.path:
        try:
            result = run_file_analysis(args.path)
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1
        type_groups = result.file_type_groups
        total_bytes = result.stats.bytes_examined
    else:
        store = SnapshotStore()
        latest = store.get_latest_file_scan()
        if latest is None:
            print("No file scan found. Run 'files scan <path>' first.")
            return 1
        type_groups_raw = store.load_file_scan_type_groups(latest["id"])
        type_groups = type_groups_raw
        total_bytes = latest["stats"]["bytes_examined"] if latest["stats"] else 0

    print(f"{'Extension':>15s}  {'Count':>8s}  {'Size':>12s}  {'%':>6s}")
    print("-" * 50)

    for t in type_groups:
        ext = t["extension"] if isinstance(t, dict) else t.get("extension", "")
        count = t["file_count"] if isinstance(t, dict) else t.get("file_count", 0)
        size = t["total_size_bytes"] if isinstance(t, dict) else t.get("total_size_bytes", 0)
        pct = (size / total_bytes * 100) if total_bytes > 0 else 0
        print(f"  {ext:>13s}  {count:>8,d}  {_format_bytes(size):>12s}  {pct:>5.1f}%")

    return 0


def cmd_files_duplicates(args: argparse.Namespace) -> int:
    """Show duplicate file groups from the latest scan or scan a directory."""
    from app.file_analysis.runner import run_file_analysis
    from app.database.sqlite import SnapshotStore

    print("Old Computer Manager v0.9.1-alpha")
    print("Duplicate file analysis\n")

    if args.path:
        try:
            result = run_file_analysis(args.path, dup_max_groups=args.max_groups)
        except ValueError as exc:
            print(f"Error: {exc}")
            return 1
        dup_groups = result.duplicate_groups
    else:
        store = SnapshotStore()
        latest = store.get_latest_file_scan()
        if latest is None:
            print("No file scan found. Run 'files scan <path>' first.")
            return 1
        dup_groups_raw = store.load_file_scan_duplicate_groups(latest["id"])
        from app.file_analysis.models import DuplicateGroup
        dup_groups = [
            DuplicateGroup(
                group_id=g["group_id"],
                size_bytes=g["size_bytes"],
                paths=g["paths"],
                match_type=g["match_type"],
                hash_value=g.get("hash_value"),
            )
            for g in dup_groups_raw
        ]

    if not dup_groups:
        print("No duplicate groups found.")
        return 0

    total_dup_bytes = sum(g.size_bytes * (len(g.paths) - 1) for g in dup_groups)
    print(f"Duplicate groups: {len(dup_groups)}")
    print(f"Potential space savings: {_format_bytes(total_dup_bytes)}\n")

    for g in dup_groups[:args.max_groups]:
        print(f"Group {g.group_id}: {len(g.paths)} files, "
              f"{_format_bytes(g.size_bytes)} each ({g.match_type})")
        if g.hash_value:
            print(f"  Hash: {g.hash_value[:16]}...")
        for p in g.paths:
            print(f"    {p}")
        print()

    return 0


def _format_bytes(n: int | float) -> str:
    """Format a byte count into a human-readable string."""
    if n is None:
        return "unknown"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} PB"


def cmd_report(args: argparse.Namespace) -> int:
    """Generate and display the unified health report."""
    from app.reporting.runner import generate_report, generate_json, generate_human
    from app.database.sqlite import SnapshotStore

    print("Old Computer Manager v0.9.1-alpha")
    print("Generating health report...\n")

    store = SnapshotStore()
    report = generate_report(store)

    if getattr(args, "json_output", False):
        print(generate_json(report))
    else:
        print(generate_human(report))

    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the local read-only API server."""
    import uvicorn

    print("Old Computer Manager v0.9.1-alpha")
    print(f"Starting API server on {args.host}:{args.port}")
    print("This server is intended for localhost use only.")
    print("Press Ctrl+C to stop.\n")

    uvicorn.run(
        "app.api.app:app",
        host=args.host,
        port=args.port,
        log_level="info",
    )
    return 0


def cmd_ai(args: argparse.Namespace) -> int:
    """Generate AI advisory from the latest completed report."""
    from app.ai.runner import run_advisory, run_advisory_json, AdvisoryRunnerError

    print("Old Computer Manager v0.9.1-alpha")
    print("AI Advisory (local-first, read-only)\n")

    try:
        if getattr(args, "json_output", False):
            print(run_advisory_json())
        else:
            advisory = run_advisory()

            # Print human-readable summary
            print(f"Generated at:  {advisory.generated_at}")
            print(f"Provider:      {advisory.metadata.provider}")
            print(f"Model:         {advisory.metadata.model}")
            print(f"Prompt version: {advisory.metadata.prompt_version}")
            print(f"Analysis:      {advisory.analysis_status or 'unknown'}")
            print()

            print("SUMMARY")
            print("-" * 60)
            print(advisory.summary)
            print()

            if advisory.observations:
                print("OBSERVATIONS")
                print("-" * 60)
                for obs in advisory.observations:
                    severity_marker = {
                        "critical": "[CRITICAL]",
                        "warning": "[WARNING]",
                        "info": "[INFO]",
                    }.get(obs.severity, "[?]")
                    print(f"  {severity_marker} {obs.title}")
                    print(f"    Evidence: {obs.evidence}")
                    print(f"    Source:   {obs.source}")
                    print()
                print()

            if advisory.recommendations:
                print("RECOMMENDATIONS")
                print("-" * 60)
                for rec in advisory.recommendations:
                    print(f"  - {rec.title}")
                    print(f"    Rationale: {rec.rationale}")
                    if rec.related_action_ids:
                        print(f"    Related actions: {', '.join(rec.related_action_ids)}")
                    print(f"    Risk: {rec.risk_level}")
                    print()

            if advisory.uncertainties:
                print("UNCERTAINTIES")
                print("-" * 60)
                for unc in advisory.uncertainties:
                    print(f"  - {unc.description}")
                    print(f"    Impact: {unc.impact}")
                print()

            if advisory.limitations:
                print("LIMITATIONS")
                print("-" * 60)
                for lim in advisory.limitations:
                    print(f"  - {lim.description}")
                print()

            if advisory.historical_summary:
                h = advisory.historical_summary
                print("HISTORICAL SUMMARY")
                print("-" * 60)
                print(f"  Runs considered:    {h.runs_considered}")
                print(f"  Observations used:  {h.observations_used}")
                print(f"  Trends analyzed:    {h.trends_count}")
                print(f"  Baselines set:      {h.baselines_established}")
                print(f"  Recurring findings: {h.recurring_findings_count}")
                print(f"  Anomalies detected: {h.anomalies_count}")
                if h.data_quality_issues > 0:
                    print(f"  Data quality issues: {h.data_quality_issues}")
                print()

            print("NOTE: This is advisory only. No actions have been executed.")

    except AdvisoryRunnerError as e:
        print(f"Error: {e}")
        return 1

    return 0


def cmd_history(args: argparse.Namespace) -> int:
    """Display historical trend analysis."""
    from app.history.runner import run_history, run_history_json

    print("Old Computer Manager v0.9.1-alpha")
    print("Historical Trend Analysis (read-only)\n")

    store = SnapshotStore()

    if getattr(args, "json_output", False):
        print(run_history_json(store, limit=getattr(args, "limit", None)))
        return 0

    summary = run_history(
        store,
        limit=getattr(args, "limit", None),
        metric=getattr(args, "metric", None),
    )

    if summary.runs_considered == 0:
        print("No completed discovery runs found.")
        print("Run 'old-computer-manager discover' first to collect data.")
        return 0

    print(f"Runs analyzed:  {summary.runs_considered}")
    print(f"Run IDs:        {', '.join(str(r) for r in summary.run_ids)}")
    print(f"Observations:   {summary.observations_available}")
    print()

    if summary.trends:
        print("TRENDS")
        print("-" * 60)
        for t in summary.trends:
            direction_marker = {
                "increasing": "[UP]",
                "decreasing": "[DOWN]",
                "stable": "[--]",
                "insufficient_data": "[??]",
            }.get(t.direction, "[?]")
            print(f"  {direction_marker} {t.metric_name}")
            print(f"    Observations: {t.observations_count}")
            print(f"    First: {t.first_value} ({t.first_timestamp})")
            print(f"    Latest: {t.latest_value} ({t.latest_timestamp})")
            if t.delta_absolute is not None:
                print(f"    Delta: {t.delta_absolute:+.2f} ({t.delta_percent:+.1f}%)")
            print()

    if summary.baseline:
        print("BASELINE COMPARISON")
        print("-" * 60)
        for b in summary.baseline:
            status_marker = {
                "unavailable": "[--]",
                "established": "[OK]",
                "improved": "[UP]",
                "degraded": "[DOWN]",
                "unchanged": "[--]",
                "insufficient_data": "[??]",
            }.get(b.baseline_status, "[?]")
            print(f"  {status_marker} {b.metric_name}")
            print(f"    Status:     {b.baseline_status}")
            if b.baseline_value is not None:
                print(f"    Baseline:   {b.baseline_value} (run {b.baseline_run_id})")
            if b.current_value is not None:
                print(f"    Current:    {b.current_value}")
            if b.delta is not None:
                print(f"    Delta:      {b.delta:+.2f} ({b.delta_percent:+.1f}%)")
            print()

    if summary.recurring_findings:
        print("RECURRING FINDINGS")
        print("-" * 60)
        for r in summary.recurring_findings:
            severity_marker = {
                "critical": "[CRITICAL]",
                "warning": "[WARNING]",
                "info": "[INFO]",
            }.get(r.severity, "[?]")
            print(f"  {severity_marker} {r.title}")
            print(f"    Analyzer:    {r.analyzer}")
            print(f"    Occurrences: {r.occurrence_count} runs")
            print(f"    First seen:  {r.first_seen}")
            print(f"    Last seen:   {r.last_seen}")
            print()

    if summary.anomalies:
        print("ANOMALIES")
        print("-" * 60)
        for a in summary.anomalies:
            severity_marker = {
                "critical": "[CRITICAL]",
                "warning": "[WARNING]",
                "info": "[INFO]",
            }.get(a.severity, "[?]")
            print(f"  {severity_marker} {a.title}")
            print(f"    {a.message}")
            print()

    print("NOTE: This is descriptive historical analysis, not predictive failure forecasting.")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="old-computer-manager",
        description="Local-first computer intelligence with safe remediation.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("discover", help="Run a full discovery scan")
    sub.add_parser("analyze", help="Analyze the latest completed discovery run")

    # files subcommand with sub-subcommands
    files_parser = sub.add_parser("files", help="File and storage intelligence (read-only)")
    files_sub = files_parser.add_subparsers(dest="files_command")

    # files scan
    scan_parser = files_sub.add_parser("scan", help="Scan a directory and analyze files")
    scan_parser.add_argument("path", help="Directory path to scan")
    scan_parser.add_argument(
        "--top-n", type=int, default=50,
        help="Number of largest files to report (default: 50)"
    )
    scan_parser.add_argument(
        "--min-size", type=int, default=100 * 1024 * 1024,
        help="Minimum file size in bytes for large-file detection (default: 100MB)"
    )

    # files large
    large_parser = files_sub.add_parser("large", help="Show large files")
    large_parser.add_argument("path", nargs="?", default=None, help="Directory to scan (or use latest scan)")
    large_parser.add_argument("--top-n", type=int, default=50, help="Number of files to show")
    large_parser.add_argument("--min-size", type=int, default=100 * 1024 * 1024, help="Minimum size in bytes")

    # files types
    types_parser = files_sub.add_parser("types", help="Show file type breakdown")
    types_parser.add_argument("path", nargs="?", default=None, help="Directory to scan (or use latest scan)")

    # files duplicates
    dup_parser = files_sub.add_parser("duplicates", help="Show duplicate file groups")
    dup_parser.add_argument("path", nargs="?", default=None, help="Directory to scan (or use latest scan)")
    dup_parser.add_argument("--max-groups", type=int, default=100, help="Maximum groups to show")

    # report subcommand
    report_parser = sub.add_parser("report", help="Generate unified health report")
    report_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output report as JSON",
    )

    # serve subcommand
    serve_parser = sub.add_parser("serve", help="Start the local read-only API server")
    serve_parser.add_argument(
        "--host", default="127.0.0.1",
        help="Bind address (default: 127.0.0.1 localhost only)",
    )
    serve_parser.add_argument(
        "--port", type=int, default=8000,
        help="Port number (default: 8000)",
    )

    # ai subcommand
    ai_parser = sub.add_parser("ai", help="Generate AI advisory (read-only)")
    ai_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output advisory as JSON",
    )

    # history subcommand
    history_parser = sub.add_parser("history", help="Historical trend analysis (read-only)")
    history_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output history as JSON",
    )
    history_parser.add_argument(
        "--limit", type=int, default=None,
        help="Maximum number of runs to consider",
    )
    history_parser.add_argument(
        "--metric", type=str, default=None,
        help="Filter to a specific metric",
    )

    # actions subcommand with sub-subcommands
    actions_parser = sub.add_parser("actions", help="Manage remediation actions")
    actions_sub = actions_parser.add_subparsers(dest="actions_command")

    # actions (list)
    # No subcommand defaults to list

    # actions preview
    preview_parser = actions_sub.add_parser(
        "preview", help="Preview an action without executing"
    )
    preview_parser.add_argument("action_id", help="Action ID to preview")
    preview_parser.add_argument(
        "--age-days", type=int, default=None,
        help="Age threshold in days (quarantine only)"
    )

    # actions execute
    execute_parser = actions_sub.add_parser(
        "execute", help="Execute an action with confirmation"
    )
    execute_parser.add_argument("action_id", help="Action ID to execute")
    execute_parser.add_argument(
        "--age-days", type=int, default=None,
        help="Age threshold in days (quarantine only)"
    )

    # actions rollback
    rollback_parser = actions_sub.add_parser(
        "rollback", help="Restore a quarantined file"
    )
    rollback_parser.add_argument(
        "record_id", type=int, help="Quarantine record ID to restore"
    )
    rollback_parser.add_argument(
        "--overwrite", action="store_true", default=False,
        help="Overwrite existing file at original path"
    )

    args = parser.parse_args()

    if args.command == "report":
        return cmd_report(args)
    if args.command == "serve":
        return cmd_serve(args)
    if args.command == "ai":
        return cmd_ai(args)
    if args.command == "analyze":
        return cmd_analyze(args)
    if args.command == "history":
        return cmd_history(args)
    if args.command == "files":
        if args.files_command == "scan":
            return cmd_files_scan(args)
        if args.files_command == "large":
            return cmd_files_large(args)
        if args.files_command == "types":
            return cmd_files_types(args)
        if args.files_command == "duplicates":
            return cmd_files_duplicates(args)
        # Default: show help
        files_parser.print_help()
        return 0
    if args.command == "actions":
        if args.actions_command == "preview":
            return cmd_actions_preview(args)
        if args.actions_command == "execute":
            return cmd_actions_execute(args)
        if args.actions_command == "rollback":
            return cmd_actions_rollback(args)
        return cmd_actions(args)
    # Default: discover
    return cmd_discover(args)


if __name__ == "__main__":
    raise SystemExit(main())
