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

    print("Old Computer Manager v0.15.1-alpha")
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

    print("Old Computer Manager v0.15.1-alpha")
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

    print("Old Computer Manager v0.15.1-alpha")
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
    from app.remediation.action_preview import preview_action
    import json as json_mod

    print("Old Computer Manager v0.15.1-alpha")
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

        # Handle both QuarantinePlan (files_eligible) and CleanupPreview (candidates)
        eligible_count = getattr(plan, "files_eligible", None) or getattr(plan, "candidates", 0)
        eligible_files = getattr(plan, "eligible_files", None) or getattr(plan, "candidate_files", [])
        print(f"Files eligible: {eligible_count}")
        print(f"Total size:    {plan.total_size_bytes:,} bytes")
        print()

        if plan.warnings:
            print("Warnings:")
            for w in plan.warnings:
                print(f"  - {w}")
            print()

        if eligible_files:
            print(f"Eligible files (showing {len(eligible_files)}):")
            for f in eligible_files[:50]:
                print(f"  {f.path}  ({f.size:,} bytes, mtime: {f.mtime_iso})")
            if len(eligible_files) > 50:
                print(f"  ... and {len(eligible_files) - 50} more")
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

    print("Old Computer Manager v0.15.1-alpha")
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

    print("Old Computer Manager v0.15.1-alpha")
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


def cmd_actions_candidates(args: argparse.Namespace) -> int:
    """Show action candidates from the deterministic policy engine."""
    import json as json_mod
    from app.reporting.builder import build_health_report

    print("Old Computer Manager v0.15.1-alpha")
    print("Action Candidates (read-only, no execution)\n")

    report = build_health_report()
    ac = report.action_candidates

    # Apply filters
    candidates = ac.candidates
    if args.status:
        candidates = [c for c in candidates if c.get("status") == args.status]
    if args.action:
        candidates = [c for c in candidates if c.get("action_id") == args.action]

    if args.json_output:
        output = {
            "available_count": ac.available_count,
            "proposed_count": ac.proposed_count,
            "blocked_count": ac.blocked_count,
            "insufficient_evidence_count": ac.insufficient_evidence_count,
            "stale_count": ac.stale_count,
            "total_count": len(candidates),
            "candidates": candidates,
        }
        print(json_mod.dumps(output, indent=2, default=str))
        return 0

    # Summary
    print(f"Available: {ac.available_count}  |  "
          f"Proposed: {ac.proposed_count}  |  "
          f"Blocked: {ac.blocked_count}  |  "
          f"Insufficient evidence: {ac.insufficient_evidence_count}  |  "
          f"Stale: {ac.stale_count}")
    print(f"Total candidates: {len(candidates)}\n")

    if not candidates:
        print("No candidates found.")
        return 0

    for c in candidates:
        status = c.get("status", "unknown")
        marker = {
            "available": "[AVAILABLE]",
            "proposed": "[PROPOSED]",
            "blocked": "[BLOCKED]",
            "insufficient_evidence": "[INSUFFICIENT]",
            "stale": "[STALE]",
        }.get(status, f"[{status.upper()}]")

        print(f"  {marker} {c.get('action_id', '?')}")
        print(f"    Title:  {c.get('title', '?')}")
        print(f"    Reason: {c.get('reason', '?')}")
        print(f"    Risk:   {c.get('risk_level', '?')}  |  "
              f"Reversible: {c.get('reversible', False)}  |  "
              f"Executable: {c.get('executable', False)}")
        limitations = c.get("limitations", [])
        if limitations:
            print(f"    Note:   {'; '.join(limitations)}")
        print()

    return 0


def cmd_actions_preview_candidate(args: argparse.Namespace) -> int:
    """Preview an action candidate (read-only, no execution)."""
    import json as json_mod
    from app.reporting.builder import build_health_report
    from app.remediation.preview import build_preview, PreviewStatus
    from app.remediation.candidates import ActionCandidate, CandidateStatus, EvidenceSource, EvidenceSourceType

    print("Old Computer Manager v0.15.1-alpha")
    print(f"Candidate preview: {args.candidate_id}\n")

    report = build_health_report()

    # Find candidate
    candidate_data = None
    for c in report.action_candidates.candidates:
        if c.get("candidate_id") == args.candidate_id:
            candidate_data = c
            break

    if candidate_data is None:
        print(f"Error: Candidate '{args.candidate_id}' not found.")
        print("Use 'actions candidates' to list available candidates.")
        return 1

    # Reconstruct ActionCandidate
    evidence_list = []
    for ev_dict in candidate_data.get("evidence", []):
        source_type_str = ev_dict.get("source_type", "discovery")
        try:
            source_type = EvidenceSourceType(source_type_str)
        except ValueError:
            source_type = EvidenceSourceType.DISCOVERY
        evidence_list.append(EvidenceSource(
            source_type=source_type,
            source_id=ev_dict.get("source_id", ""),
            observation=ev_dict.get("observation", ""),
        ))

    try:
        status_enum = CandidateStatus(candidate_data.get("status", "unavailable"))
    except ValueError:
        status_enum = CandidateStatus.AVAILABLE

    candidate = ActionCandidate(
        candidate_id=candidate_data.get("candidate_id", ""),
        action_id=candidate_data.get("action_id", ""),
        status=status_enum,
        title=candidate_data.get("title", ""),
        reason=candidate_data.get("reason", ""),
        risk_level=candidate_data.get("risk_level", ""),
        reversible=candidate_data.get("reversible", False),
        requires_admin=candidate_data.get("requires_admin", False),
        limitations=candidate_data.get("limitations", []),
        evidence=evidence_list,
        discovery_run_id=candidate_data.get("discovery_run_id"),
    )

    # Load persisted eligible temp file evidence for preview
    from app.database.sqlite import SnapshotStore
    _store = SnapshotStore()
    file_analysis_for_preview = None
    temp_evidence = _store.get_latest_eligible_temp_evidence()
    if temp_evidence is not None:
        file_analysis_for_preview = {
            "scan_source": temp_evidence.get("scan_root", "unknown"),
            "eligible_temp_files": temp_evidence.get("eligible_files", []),
        }

    preview = build_preview(candidate, file_analysis=file_analysis_for_preview)

    if args.json_output:
        output = {
            "preview_id": preview.preview_id,
            "candidate_id": preview.candidate_id,
            "action_id": preview.action_id,
            "generated_at": preview.generated_at,
            "status": preview.status.value,
            "title": preview.title,
            "summary": preview.summary,
            "target": preview.target,
            "affected_count": preview.affected_count,
            "affected_bytes": preview.affected_bytes,
            "affected_items": [
                {"path": item.path, "size_bytes": item.size_bytes}
                for item in preview.affected_items
            ],
            "expected_effect": preview.expected_effect,
            "side_effects": preview.side_effects,
            "risk_level": preview.risk_level,
            "blast_radius": preview.blast_radius,
            "reversible": preview.reversible,
            "rollback_available": preview.rollback_available,
            "rollback_description": preview.rollback_description,
            "requires_admin": preview.requires_admin,
            "confirmation_required": preview.confirmation_required,
            "limitations": preview.limitations,
            "warnings": preview.warnings,
            "omitted_count": preview.omitted_count,
            "fingerprint": preview.fingerprint,
            "permanent_deletion": preview.permanent_deletion,
            "implementation_status": preview.implementation_status,
            "implementation_status_text": preview.implementation_status_text,
        }
        print(json_mod.dumps(output, indent=2, default=str))
        return 0

    # Human-readable output
    status_marker = {
        PreviewStatus.READY: "[READY]",
        PreviewStatus.STALE: "[STALE]",
        PreviewStatus.INSUFFICIENT_EVIDENCE: "[INSUFFICIENT EVIDENCE]",
        PreviewStatus.BLOCKED: "[BLOCKED]",
        PreviewStatus.UNAVAILABLE: "[UNAVAILABLE]",
        PreviewStatus.ERROR: "[ERROR]",
    }.get(preview.status, f"[{preview.status.value.upper()}]")

    print(f"  Status:   {status_marker}")
    print(f"  Action:   {preview.action_id}")
    print(f"  Title:    {preview.title}")
    print(f"  Summary:  {preview.summary}")
    print(f"  Target:   {preview.target}")
    print()

    if preview.affected_count > 0:
        print(f"  Affected: {preview.affected_count} items ({preview.affected_bytes:,} bytes)")
        if preview.affected_items:
            print(f"  Targets:")
            for item in preview.affected_items[:10]:
                print(f"    - {item.path} ({item.size_bytes:,} bytes)")
            if preview.omitted_count > 0:
                print(f"    ... and {preview.omitted_count} more")
        print()

    print(f"  Expected: {preview.expected_effect}")
    print(f"  Risk:     {preview.risk_level}")
    print(f"  Reversible: {'yes' if preview.reversible else 'no'}")
    print(f"  Rollback:   {'available' if preview.rollback_available else 'unavailable'}")
    if preview.rollback_description:
        print(f"  Rollback:   {preview.rollback_description}")
    print(f"  Confirmation required: {'yes' if preview.confirmation_required else 'no'}")
    if preview.implementation_status_text:
        print(f"  Implementation: {preview.implementation_status_text}")
    print()

    if preview.side_effects:
        print("  Side effects:")
        for se in preview.side_effects:
            print(f"    - {se}")
        print()

    if preview.warnings:
        print("  Warnings:")
        for w in preview.warnings:
            print(f"    - {w}")
        print()

    if preview.limitations:
        print("  Limitations:")
        for lim in preview.limitations:
            print(f"    - {lim}")
        print()

    return 0


def cmd_actions_confirm_candidate(args: argparse.Namespace) -> int:
    """Confirm an action candidate with an existing preview (explicit human confirmation)."""
    import json as json_mod
    from app.reporting.builder import build_health_report
    from app.remediation.preview import build_preview, PreviewStatus
    from app.remediation.candidates import ActionCandidate, CandidateStatus, EvidenceSource, EvidenceSourceType
    from app.remediation.confirmation_service import (
        ConfirmationError,
    )

    print("Old Computer Manager v0.15.1-alpha")
    print(f"Confirm candidate: {args.candidate_id}\n")

    report = build_health_report()

    # Find candidate
    candidate_data = None
    for c in report.action_candidates.candidates:
        if c.get("candidate_id") == args.candidate_id:
            candidate_data = c
            break

    if candidate_data is None:
        print(f"Error: Candidate '{args.candidate_id}' not found.")
        print("Use 'actions candidates' to list available candidates.")
        return 1

    # Reconstruct ActionCandidate
    evidence_list = []
    for ev_dict in candidate_data.get("evidence", []):
        source_type_str = ev_dict.get("source_type", "discovery")
        try:
            source_type = EvidenceSourceType(source_type_str)
        except ValueError:
            source_type = EvidenceSourceType.DISCOVERY
        evidence_list.append(EvidenceSource(
            source_type=source_type,
            source_id=ev_dict.get("source_id", ""),
            observation=ev_dict.get("observation", ""),
        ))

    try:
        status_enum = CandidateStatus(candidate_data.get("status", "unavailable"))
    except ValueError:
        status_enum = CandidateStatus.AVAILABLE

    candidate = ActionCandidate(
        candidate_id=candidate_data.get("candidate_id", ""),
        action_id=candidate_data.get("action_id", ""),
        status=status_enum,
        title=candidate_data.get("title", ""),
        reason=candidate_data.get("reason", ""),
        risk_level=candidate_data.get("risk_level", ""),
        reversible=candidate_data.get("reversible", False),
        requires_admin=candidate_data.get("requires_admin", False),
        limitations=candidate_data.get("limitations", []),
        evidence=evidence_list,
        discovery_run_id=candidate_data.get("discovery_run_id"),
    )

    preview = build_preview(candidate)

    # Attempt confirmation
    from app.remediation.confirmation_service import get_confirmation_service
    service = get_confirmation_service()
    try:
        record = service.confirm(candidate, preview)
    except ConfirmationError as e:
        print(f"Confirmation failed: {e}")
        return 1

    if args.json_output:
        output = {
            "confirmation_id": record.confirmation_id,
            "candidate_id": record.candidate_id,
            "action_id": record.action_id,
            "preview_id": record.preview_id,
            "preview_fingerprint": record.preview_fingerprint,
            "confirmed_at": record.confirmed_at,
            "consumed": record.consumed,
        }
        print(json_mod.dumps(output, indent=2, default=str))
        return 0

    # Human-readable output
    print(f"  Confirmation ID:   {record.confirmation_id}")
    print(f"  Candidate:         {record.candidate_id}")
    print(f"  Action:            {record.action_id}")
    print(f"  Preview ID:        {record.preview_id}")
    print(f"  Preview fingerprint: {record.preview_fingerprint[:16]}...")
    print(f"  Confirmed at:      {record.confirmed_at}")
    print(f"  Consumed:          {'yes' if record.consumed else 'no'}")
    print()
    print("  Confirmation created. This token is single-use.")
    print("  The action has NOT been executed. Use 'actions execute' to run it.")
    print()

    return 0


def cmd_actions_execute_candidate(args: argparse.Namespace) -> int:
    """Execute a confirmed action candidate through the controlled pipeline."""
    import json as json_mod
    from app.reporting.builder import build_health_report
    from app.remediation.preview import build_preview, PreviewStatus
    from app.remediation.candidates import ActionCandidate, CandidateStatus, EvidenceSource, EvidenceSourceType
    from app.remediation.controlled_execution import (
        ControlledExecutionService,
        ExecutionDeniedError,
    )

    print("Old Computer Manager v0.15.1-alpha")
    print(f"Execute candidate: {args.candidate_id}\n")

    report = build_health_report()

    # Find candidate
    candidate_data = None
    for c in report.action_candidates.candidates:
        if c.get("candidate_id") == args.candidate_id:
            candidate_data = c
            break

    if candidate_data is None:
        print(f"Error: Candidate '{args.candidate_id}' not found.")
        print("Use 'actions candidates' to list available candidates.")
        return 1

    # Reconstruct ActionCandidate
    evidence_list = []
    for ev_dict in candidate_data.get("evidence", []):
        source_type_str = ev_dict.get("source_type", "discovery")
        try:
            source_type = EvidenceSourceType(source_type_str)
        except ValueError:
            source_type = EvidenceSourceType.DISCOVERY
        evidence_list.append(EvidenceSource(
            source_type=source_type,
            source_id=ev_dict.get("source_id", ""),
            observation=ev_dict.get("observation", ""),
        ))

    try:
        status_enum = CandidateStatus(candidate_data.get("status", "unavailable"))
    except ValueError:
        status_enum = CandidateStatus.AVAILABLE

    candidate = ActionCandidate(
        candidate_id=candidate_data.get("candidate_id", ""),
        action_id=candidate_data.get("action_id", ""),
        status=status_enum,
        title=candidate_data.get("title", ""),
        reason=candidate_data.get("reason", ""),
        risk_level=candidate_data.get("risk_level", ""),
        reversible=candidate_data.get("reversible", False),
        requires_admin=candidate_data.get("requires_admin", False),
        limitations=candidate_data.get("limitations", []),
        evidence=evidence_list,
        discovery_run_id=candidate_data.get("discovery_run_id"),
    )

    preview = build_preview(candidate)

    # Get confirmation from confirmation store
    from app.remediation.confirmation_service import get_confirmation_service
    conf_service = get_confirmation_service()
    conf_records = conf_service.store.get_for_candidate(candidate.candidate_id)

    if not conf_records:
        print(f"Error: No confirmation found for candidate '{candidate.candidate_id}'.")
        print("Use 'actions confirm-candidate' to create a confirmation first.")
        return 1

    # Use the most recent unconsumed confirmation
    confirmation_id = None
    for record in reversed(conf_records):
        if not record.consumed:
            confirmation_id = record.confirmation_id
            break

    if confirmation_id is None:
        print(f"Error: All confirmations for candidate '{candidate.candidate_id}' have been consumed.")
        print("Use 'actions confirm-candidate' to create a new confirmation.")
        return 1

    # Execute through controlled pipeline
    service = ControlledExecutionService()
    try:
        result = service.execute(candidate, preview, confirmation_id)
    except ExecutionDeniedError as e:
        print(f"Execution denied: {e}")
        return 1

    if args.json_output:
        output = {
            "execution_id": result.execution_id,
            "action_id": result.action_id,
            "action_version": result.action_version,
            "candidate_id": result.candidate_id,
            "confirmation_id": result.confirmation_id,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "status": result.status,
            "files_examined": result.files_examined,
            "files_moved": result.files_moved,
            "files_skipped": result.files_skipped,
            "files_failed": result.files_failed,
            "bytes_moved": result.bytes_moved,
            "quarantine_record_ids": result.quarantine_record_ids,
            "result_summary": result.result_summary,
            "errors": result.errors,
            "rollback_available": result.rollback_available,
        }
        print(json_mod.dumps(output, indent=2, default=str))
        return 0

    # Human-readable output
    print(f"  Execution ID:    {result.execution_id}")
    print(f"  Action:          {result.action_id}")
    print(f"  Status:          {result.status}")
    print(f"  Files examined:  {result.files_examined}")
    print(f"  Files moved:     {result.files_moved}")
    print(f"  Files skipped:   {result.files_skipped}")
    print(f"  Files failed:    {result.files_failed}")
    print(f"  Bytes moved:     {result.bytes_moved}")
    if result.quarantine_record_ids:
        print(f"  Quarantine records: {result.quarantine_record_ids}")
    print(f"  Rollback available: {'yes' if result.rollback_available else 'no'}")
    if result.errors:
        print(f"  Errors:")
        for err in result.errors:
            print(f"    - {err}")
    print()
    print(f"  {result.result_summary}")
    print()

    return 0


def cmd_files_scan(args: argparse.Namespace) -> int:
    """Scan a directory and run file analysis."""
    from app.file_analysis.runner import run_file_analysis
    from app.database.sqlite import SnapshotStore

    print("Old Computer Manager v0.15.1-alpha")
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

    # Persist eligible temp file evidence if scan targets approved TEMP dir
    from app.remediation.quarantine import get_user_temp_dir, scan_eligible_files
    from app.remediation.cleanup_temp import DEFAULT_AGE_DAYS
    temp_dir = get_user_temp_dir()
    if temp_dir is not None:
        scan_root_resolved = str(Path(result.scan_root).resolve())
        temp_dir_resolved = str(temp_dir.resolve())
        if scan_root_resolved == temp_dir_resolved:
            eligible_files, eligible_count, warnings = scan_eligible_files(
                temp_dir, DEFAULT_AGE_DAYS
            )
            eligible_total_bytes = sum(f.size for f in eligible_files)
            from datetime import datetime, timezone
            eligible_evidence = {
                "scan_root": result.scan_root,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "age_threshold_days": DEFAULT_AGE_DAYS,
                "eligible_file_count": eligible_count,
                "eligible_total_bytes": eligible_total_bytes,
                "eligible_files": [
                    {
                        "path": str(f.path),
                        "size_bytes": f.size,
                        "mtime": f.mtime,
                        "mtime_iso": f.mtime_iso,
                    }
                    for f in eligible_files[:200]
                ],
            }
            store.save_file_scan_eligible_temp_files(scan_id, eligible_evidence)

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

    print("Old Computer Manager v0.15.1-alpha")
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

    print("Old Computer Manager v0.15.1-alpha")
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

    print("Old Computer Manager v0.15.1-alpha")
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

    print("Old Computer Manager v0.15.1-alpha")
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

    print("Old Computer Manager v0.15.1-alpha")
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

    print("Old Computer Manager v0.15.1-alpha")
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

    print("Old Computer Manager v0.15.1-alpha")
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


def cmd_diagnostics(args: argparse.Namespace) -> int:
    """Run read-only advanced diagnostics."""
    from app.diagnostics.runner import run_diagnostics, save_diagnostic_run

    print("Old Computer Manager v0.15.1-alpha")
    print("Advanced Diagnostics (read-only)\n")

    category = getattr(args, "diagnostics_category", None)
    valid_categories = {"disk", "thermal", "performance", "devices", "windows", "event_log", "reliability", "boot_timing", "network_health", "driver_consistency"}
    if category and category not in valid_categories:
        print(f"Unknown category: {category}")
        print(f"Valid categories: {', '.join(sorted(valid_categories))}")
        return 1

    print("Running diagnostics...")
    run = run_diagnostics()

    # Filter by category if specified
    results = run.results
    if category:
        results = [r for r in results if r.category.value == category]

    # Save to database
    store = SnapshotStore()
    run_id = save_diagnostic_run(run, store)
    if run_id:
        print(f"Diagnostics saved (run_id={run_id})\n")

    if getattr(args, "json_output", False):
        output = {
            "run_id": run_id,
            "status": run.status,
            "results": [
                {
                    "diagnostic_id": r.diagnostic_id,
                    "category": r.category.value,
                    "status": r.status.value,
                    "title": r.title,
                    "summary": r.summary,
                    "evidence": r.evidence,
                    "source": r.source,
                    "limitations": r.limitations,
                    "errors": r.errors,
                }
                for r in results
            ],
            "errors": run.errors,
        }
        print(json.dumps(output, indent=2, default=str))
        return 0

    # Human-readable output
    status_icons = {
        "ok": "[OK]",
        "warning": "[WARN]",
        "critical": "[CRIT]",
        "unavailable": "[N/A]",
        "not_supported": "[N/S]",
        "failed": "[FAIL]",
    }

    current_category = None
    for result in results:
        cat = result.category.value
        if cat != current_category:
            current_category = cat
            print(f"\n{'=' * 60}")
            print(f"  {cat.upper()}")
            print(f"{'=' * 60}")

        icon = status_icons.get(result.status.value, "[?]")
        print(f"\n  {icon} {result.title}")
        print(f"    {result.summary}")
        if result.source:
            print(f"    Source: {result.source}")
        if result.limitations:
            for lim in result.limitations:
                if lim:
                    print(f"    Note: {lim}")
        if result.errors:
            for err in result.errors:
                print(f"    Error: {err}")

    if run.errors:
        print(f"\nCollector errors ({len(run.errors)}):")
        for err in run.errors:
            print(f"  - {err.get('collector', '?')}: {err.get('error_message', '?')}")

    counts = {}
    for r in results:
        s = r.status.value
        counts[s] = counts.get(s, 0) + 1
    print(f"\nSummary: {counts}")

    print("\nNOTE: Diagnostics identify evidence and observations; they do not perform repairs.")

    return 0


_STAGE_MARKERS = {
    "completed": "OK",
    "partial": "PARTIAL",
    "failed": "FAIL",
    "skipped": "SKIPPED",
    "budget_exceeded": "BUDGET",
    "stale": "STALE",
}


def cmd_health_run(args: argparse.Namespace) -> int:
    """Run a health session (assessment only, never remediation)."""
    from app.health.models import HealthStageStatus
    from app.health.profiles import get_profile
    from app.health.runner import HealthSessionRunner

    print("Old Computer Manager v0.15.1-alpha")

    profile_name = getattr(args, "profile", None) or "quick"
    try:
        get_profile(profile_name)
    except ValueError:
        print(f"Unknown profile: {profile_name}")
        print("Valid profiles: quick, standard, full, diagnostic, advisory")
        return 2

    runner = HealthSessionRunner(profile=profile_name)
    session = runner.run_session()

    if getattr(args, "json_output", False):
        print(json.dumps(session.to_dict(), indent=2))
    else:
        print("Health Session")
        print("------------------------------------")
        print(f"\nSession:  {session.session_id}")
        print(f"Profile:  {session.profile}")
        print(f"Status:   {session.status.value}")
        print("\nStages:")
        for stage in session.stages:
            marker = _STAGE_MARKERS.get(stage.status.value, "..")
            seconds = stage.duration_ms / 1000.0
            print(f"  [{marker}] {stage.stage_type.value:<12} {seconds:.2f}s")
            if stage.status != HealthStageStatus.COMPLETED and stage.error:
                print(f"         Reason: {stage.error}")
        print(f"\nData quality: {session.data_quality.value}")
        total_s = sum(stage.duration_ms for stage in session.stages) / 1000.0
        print(f"Total stage time: {total_s:.2f}s")
        print(
            "\nNOTE: Health sessions assess only; "
            "they never execute remediation."
        )

    if session.status in (
        HealthStageStatus.COMPLETED,
        HealthStageStatus.PARTIAL,
    ):
        return 0
    return 1


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

    # actions candidates
    candidates_parser = actions_sub.add_parser(
        "candidates", help="Show action candidates from policy engine"
    )
    candidates_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output as JSON"
    )
    candidates_parser.add_argument(
        "--status", type=str, default=None,
        help="Filter by candidate status (available, proposed, blocked, etc.)"
    )
    candidates_parser.add_argument(
        "--action", type=str, default=None,
        help="Filter by action ID"
    )

    # actions preview-candidate
    preview_candidate_parser = actions_sub.add_parser(
        "preview-candidate", help="Preview an action candidate (read-only)"
    )
    preview_candidate_parser.add_argument(
        "candidate_id", help="Candidate ID to preview"
    )
    preview_candidate_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output as JSON"
    )

    # actions confirm-candidate
    confirm_candidate_parser = actions_sub.add_parser(
        "confirm-candidate", help="Confirm an action candidate (explicit human confirmation)"
    )
    confirm_candidate_parser.add_argument(
        "candidate_id", help="Candidate ID to confirm"
    )
    confirm_candidate_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output as JSON"
    )

    # actions execute-candidate
    execute_candidate_parser = actions_sub.add_parser(
        "execute-candidate", help="Execute a confirmed action candidate (controlled execution)"
    )
    execute_candidate_parser.add_argument(
        "candidate_id", help="Candidate ID to execute"
    )
    execute_candidate_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output as JSON"
    )

    # diagnostics subcommand
    diag_parser = sub.add_parser("diagnostics", help="Run read-only advanced diagnostics")
    diag_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output diagnostics as JSON",
    )
    diag_parser.add_argument(
        "diagnostics_category", nargs="?", default=None,
        help="Specific category: disk, thermal, performance, devices, windows, event_log, reliability, boot_timing, network_health, driver_consistency",
    )

    # health subcommand with sub-subcommands
    health_parser = sub.add_parser(
        "health", help="Health sessions (assessment only, never remediation)"
    )
    health_sub = health_parser.add_subparsers(dest="health_command")

    # health run
    health_run_parser = health_sub.add_parser(
        "run", help="Run a health session for a profile"
    )
    health_run_parser.add_argument(
        "--profile", type=str, default="quick",
        help="Run profile: quick, standard, full, diagnostic, advisory (default: quick)",
    )
    health_run_parser.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output session as JSON",
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
    if args.command == "diagnostics":
        return cmd_diagnostics(args)
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
        if args.actions_command == "candidates":
            return cmd_actions_candidates(args)
        if args.actions_command == "preview-candidate":
            return cmd_actions_preview_candidate(args)
        if args.actions_command == "confirm-candidate":
            return cmd_actions_confirm_candidate(args)
        if args.actions_command == "execute-candidate":
            return cmd_actions_execute_candidate(args)
        return cmd_actions(args)
    if args.command == "health":
        if args.health_command == "run":
            return cmd_health_run(args)
        # Default: show help
        health_parser.print_help()
        return 0
    # Default: discover
    return cmd_discover(args)


if __name__ == "__main__":
    raise SystemExit(main())
