# Release Notes: v0.15.1-alpha

**Execution Accounting Hardening — Patch Release**

Released: 2026-09-20

## Summary

Old Computer Manager v0.15.1-alpha fixes two execution-accounting defects discovered during the first live remediation test. The execution path now produces authoritative, deterministic accounting based on actual file mutation outcomes, not timestamp heuristics.

## What Changed

### Execution Accounting
- `execute_cleanup()` now returns per-file `MoveRecord`s created immediately after each successful `shutil.move`
- No second TEMP/quarantine scan determines the execution outcome
- `files_moved == len(move_records)` — accounting is derived from actual operations

### Quarantine Records
- Records created from `MoveRecord` data with full `original_path` (was always `""` before)
- Removed `mtime < 5 seconds` heuristic for quarantine record creation
- Persistence failure is a distinct error state with explicit reporting

### Reconciliation
- New `reconcile_quarantine()` function detects orphaned files, broken records, and empty `original_path` conditions
- Read-only — no automatic restore or delete

## First Live Test Findings

During the first live test, the system:
- Successfully moved 3 test files from TEMP to quarantine
- Successfully rolled back all 3 files to their original locations
- Reported `failed` with `files_moved=0` despite actual mutation (now fixed)
- Created 0 quarantine records despite successful moves (now fixed)

## Test Results

- 1001 passed, 10 skipped
- 25 new tests covering execution accounting, persistence failure, reconciliation, and synthetic integration
- Synthetic integration test: 3 files → move → quarantine records → reconciliation → rollback → all restored

---

# Release Notes: v0.15.0-alpha

**Controlled Execution Pipeline — First Real System Changes**

Released: 2026-09-20

## Summary

Old Computer Manager v0.15.0-alpha completes the remediation intelligence pipeline (Phases 11A-11D). This release adds explicit human confirmation (11C) and controlled execution (11D), enabling the first real system changes through the full Candidate → Preview → Confirmation → Execution → Audit → Rollback chain.

**This is the first release where the system can perform real file operations.** All actions require explicit human confirmation and pass 14 authorization conditions before execution.

## Major Capabilities

### Diagnostic-to-Action Intelligence (Phases 11A-11B)
- ActionCandidate model with deterministic status (available/proposed/blocked/insufficient_evidence/stale)
- PolicyEngine evaluates diagnostic data against action catalog
- Candidate Preview explains exactly what WOULD happen before execution
- Preview is frozen, informational only, never an authorization token

### Explicit Human Confirmation (Phase 11C)
- ConfirmationService bridges Preview → Confirmation → Executor
- Preview must exist, be READY, and match the candidate
- Candidate must be AVAILABLE (not proposed/blocked/insufficient_evidence/stale)
- Confirmation is bound to a specific preview fingerprint
- Token is single-use, consumed atomically
- No `--yes`/`--force` bypass anywhere

### Controlled Execution (Phase 11D)
- 14 authorization conditions validated before execution
- Production action allowlist: `user_temp_quarantine`, `disk.cleanup_temp` only
- TOCTOU revalidation immediately before file mutation
- Atomic confirmation consumption prevents double execution
- Full audit trail with execution lifecycle
- Rollback available for temp quarantine actions

## Safety Architecture

```
Evidence → ActionCandidate → Preview → Confirmation → Execution → Audit → Rollback
```

### Authorization Conditions (all 14 must pass)
1. Registered action in catalog
2. implementation_status = implemented
3. Production action (allowlist)
4. eligibility = eligible
5. Candidate status = AVAILABLE
6. Preview status = READY
7. Preview matches candidate
8. Preview is fresh
9. Explicit confirmation exists
10. Confirmation token is valid
11. Confirmation token is unconsumed
12. Action version matches across components
13. Parameters match confirmed candidate
14. Executor validation passes

### Security Constraints
- Only production actions may execute
- No subprocess/shell/os.system in confirmation or execution layers
- No arbitrary paths, commands, or executables
- No `--yes`/`--force`/`--skip-confirmation` bypass
- AI cannot create confirmation tokens or execute actions
- Confirmation alone does not bypass executor validation

## Test Results

```
955 passed
9 skipped
0 failures
```

### Security Test Coverage
- Production action allowlist verification
- Double execution prevention (atomic consumption)
- TOCTOU revalidation (file existence, path containment, symlink detection)
- No arbitrary parameter injection
- CLI has no bypass flags
- Confirmation consumes atomically
- Preview is informational only

## Usage

```bash
# List action candidates
old-computer-manager actions candidates

# Preview a candidate
old-computer-manager actions preview-candidate <candidate_id>

# Confirm a candidate
old-computer-manager actions confirm-candidate <candidate_id>

# Execute a confirmed candidate
old-computer-manager actions execute-candidate <candidate_id>
```

## Known Limitations

- Only 2 production actions: `user_temp_quarantine` and `disk.cleanup_temp`
- Confirmation store is in-memory (not yet SQLite-backed)
- No rollback UI in dashboard
- Windows-only platform support

## Safety Posture

- API is read-only, localhost-only
- No remote access
- No arbitrary shell execution
- No AI execution path
- All actions require explicit human confirmation
- 14 authorization conditions enforced
- Full audit trail
- Rollback available for file operations
