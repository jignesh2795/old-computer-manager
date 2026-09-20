# Roadmap

This document tracks completed milestones and potential future directions for Old Computer Manager.

## Completed Milestones

### v0.11.0-alpha — Read-Only Advanced Diagnostics ✓

**Status**: 2026-09-19 (release freeze)

**Capabilities**:
- 5 read-only diagnostic modules: disk health, thermal, performance, devices, Windows health
- Per-module failure isolation — failure in one never aborts others
- DiagnosticStatus distinguishes unavailable from hardware problem
- Memory diagnostic correctly handles `psutil.swap_memory()` failures (corporate Windows)
- Disk I/O reports cumulative + rate-based metrics with 1s sampling window
- Disk I/O rate-based warnings (100 MB/s threshold); cumulative bytes are informational telemetry
- Snapshot-vs-trend wording: observations are clearly snapshots, not long-term conditions
- All thresholds centralized in constants.py
- 6 new GET-only API endpoints for diagnostics
- CLI `diagnostics [--json] [category]` command
- Dashboard Diagnostics section
- AI context includes diagnostics summary
- History tracks diagnostic metrics
- 741 total backend tests, 13 frontend tests

---

### v0.12.0-alpha — Useful Diagnostics Expansion ✓

**Status**: 2026-09-20 (release freeze)

**Capabilities**:
- 5 new read-only diagnostic modules: event_log, reliability, boot_timing, network_health, driver_consistency
- Bounded event log collection (max 200 events, 30-day lookback, grouped by source)
- Recurring error source detection across system and application logs
- Reliability/crash-history diagnostics via single Win32_ReliabilityRecord query
- Boot timing: last boot time, uptime, startup program count (psutil + registry)
- Network health: adapter status (psutil, zero PowerShell), DNS config, DNS resolution test
- Driver consistency: age and error checks via single Win32_PnPEntity query
- `collection_time_ms` on every DiagnosticResult for regression detection
- `total_time_ms` on DiagnosticRun for overall run timing
- Database schema migration for collection_time_ms column
- API responses include collection_time_ms
- WMI query consolidation: reliability 3→1, driver_consistency 2→1
- Network adapter status switched from PowerShell to psutil (zero overhead)
- 25 new regression tests for all Phase 10B categories
- 766 total backend tests, 13 frontend tests
- Observed ~15s total diagnostic runtime on HP Pavilion 15-ab023tx

**Design decisions**:
- Diagnostics remain on-demand (not auto-run by dashboard/report/history/AI)
- Event log collection bounded to prevent raw event flood
- DNS resolution test may generate DNS traffic (noted in limitations)
- Unavailable data treated as normal on older hardware
- Driver age is an observation, not proof of faulty/outdated driver
- Boot/startup terminology used (actual boot duration not available)

---

### v0.13.0-alpha — Diagnostic-to-Action Intelligence ✓

**Status**: 2026-09-20 (release freeze)

**Capabilities**:
- ActionCandidate model with deterministic status (available/proposed/blocked/insufficient_evidence/stale)
- Evidence binding via EvidenceSource (source_type, source_id, observation, value)
- PolicyEngine: evaluate_candidates() evaluates diagnostic data against action catalog
- Rule A: disk.cleanup_temp — triggers on storage pressure (>80%) + eligible temp files
- Rule B: user_temp_quarantine — triggers on eligible temp file evidence
- Blocked actions: startup.disable_entry, service.stop_temporary, service.disable_unused, software.uninstall, network.proxy_configure, power.plan_optimize
- Proposed actions: disk.cleanup_logs, browser.cache_clear, update.check_only
- `executable` property always returns `False` — no execution authority
- MAX_ACTION_CANDIDATES=20, MAX_EVIDENCE_ITEMS=10
- GET /api/v1/remediation/candidates (with status/action_id filters)
- GET /api/v1/remediation/candidates/{candidate_id}
- CLI: `actions candidates [--json] [--status X] [--action X]`
- AI prompt v1.3 with candidate rules (25-35)
- ActionCandidateSummary in HealthReport
- 62 new tests, 828 total backend tests
- Security audit: no executor/subprocess/shell in candidates.py or policy.py

---

### v0.14.0-alpha — Candidate Preview Intelligence ✓

**Status**: 2026-09-20 (release freeze)

**Capabilities**:
- Preview model (PreviewStatus, Preview, PreviewItem, PreviewSummary)
- PreviewBuilder: deterministic, read-only, no LLM
- Available candidate preview: full target list with paths, sizes, counts, bytes
- Proposed candidate preview: design-only, non-executable
- Blocked candidate preview: explains why action is blocked
- Insufficient evidence preview: identifies missing evidence
- Stale evidence preview: refuses expired targets
- MAX_PREVIEW_ITEMS = 20 for bounded output
- Preview fingerprint for change detection
- GET /api/v1/remediation/candidates/{candidate_id}/preview
- CLI: `actions preview-candidate <candidate_id> [--json]`
- 45 new tests, 873 total backend tests
- Security audit: no executor/subprocess/confirmation in preview.py

**Design decisions**:
- Preview is informational only, never an authorization token
- Preview does not create execution audit records
- Preview is frozen (immutable)
- AI cannot modify preview content
- Preview does not automatically scan filesystems
- Preview does not refresh stale evidence

**Design decisions**:
- Candidate layer MUST NOT import executor module
- Policy engine decides availability, not AI
- AI cannot promote proposed/blocked/insufficient_evidence/stale → available
- Blocked actions must NEVER become available candidates
- Historical evidence alone cannot create immediate cleanup targets
- No automatic diagnostics or filesystem scans triggered by candidate requests

---

### v0.15.1-alpha — Execution Accounting Hardening ✓

**Status**: 2026-09-20 (patch release)

**Capabilities**:
- MoveRecord-based authoritative execution accounting
- Per-file quarantine record creation from actual move outcomes
- Removed `mtime < 5 seconds` heuristic
- Persistence failure handling with explicit error reporting
- Quarantine reconciliation (orphaned files, broken records, empty original_path)
- `original_path` now preserved correctly for rollback
- Execution status: `succeeded` / `partially_succeeded` / `failed` based on actual outcomes
- 25 new tests (execution accounting + synthetic integration), 1001 total backend tests

**Design decisions**:
- Execution result derived from MoveRecord list, not from re-scanning the filesystem
- Successful `shutil.move` is the authoritative signal for quarantine record creation
- Persistence failure is a distinct error state from move failure
- Reconciliation is read-only (no automatic restore/delete)

---

### v0.15.0-alpha — Controlled Execution Pipeline ✓

**Status**: 2026-09-20 (release freeze)

**Capabilities**:
- ConfirmationService: bridges Preview → Confirmation → Executor
- Explicit human confirmation required for all implemented actions
- Confirmation bound to specific preview fingerprint
- Single-use confirmation tokens, consumed atomically
- ControlledExecutionService: 14 authorization conditions validated
- Production action allowlist: user_temp_quarantine, disk.cleanup_temp only
- TOCTOU revalidation immediately before file mutation
- Atomic confirmation consumption prevents double execution
- Full audit trail with execution lifecycle
- Rollback available for temp quarantine actions
- API: POST /api/v1/remediation/candidates/{candidate_id}/execute
- CLI: actions confirm-candidate, actions execute-candidate
- 82 new tests (confirmation + controlled execution), 955 total backend tests
- Security audit: no bypass flags, no subprocess/shell, atomic consumption

**Design decisions**:
- Confirmation layer MUST NOT import executor
- Controlled execution layer MUST NOT import AI modules, subprocess, shell
- No --yes/--force/--skip-confirmation bypass anywhere
- No arbitrary paths, commands, executables in confirmation or execution
- AI cannot create confirmation tokens or execute actions
- Confirmation alone does not bypass executor validation
- All 14 authorization conditions must pass before execution

---

### v0.9.0-alpha — Historical AI Reasoning ✓

**Status**: Released 2026-09-16

**Capabilities**:
- AI system prompt v1.1 with historical reasoning rules
- FACT/INFERENCE/UNCERTAINTY distinction in historical explanations
- Trend observations with direction and delta
- Baseline reasoning with comparison and status
- Recurring finding explanations with occurrence count
- Anomaly interpretation without speculative cause attribution
- Battery baseline reasoning (unavailable/established/degraded)
- `HistoricalSummary` dataclass in AI advisory output
- 44 new tests covering all historical AI reasoning features
- 542 tests passing

---

### v0.8.0-alpha — Historical Trends + Baseline Comparison ✓

**Status**: Released 2026-09-16

**Capabilities**:
- Historical trend analysis across multiple discovery runs
- Baseline comparison with battery-specific rules
- Recurring findings detection
- Simple anomaly detection (sudden changes)
- 14 trackable metrics (storage, battery, hardware, counts)
- CLI: `history`, `history --json`, `--limit`, `--metric`
- API: `/api/v1/history/summary`, `/trends`, `/baseline`, `/anomalies`
- Dashboard Historical section
- AI context with historical summaries
- 498 tests passing

---

### v0.7.0-alpha — Lightweight Local Dashboard ✓

**Status**: Released 2026-09-16

**Capabilities**:
- 11 read-only discovery collectors
- SQLite knowledge base with history
- 6 analysis engines with configurable thresholds
- Remediation safety framework
- User temp quarantine with rollback
- Battery deep inspection with health analysis
- File/storage intelligence (large files, duplicates, types)
- Unified health report (human + JSON)
- Local read-only FastAPI API
- 397 tests passing

---

## Future Directions

The following features are **not implemented** and represent potential development directions. No commitments are made to timelines or implementation order.

### Near-Term Candidates

#### Additional Remediation Actions

### Long-Term Candidates

#### Broader Platform Support
- macOS collectors and analyzers
- Linux collectors and analyzers
- Cross-platform database schema

**Rationale**: The data model is designed to be OS-neutral; extending to other platforms is architecturally feasible.

**Requirement**: Must maintain the same safety principles and read-by-default behavior.

#### Advanced Remediation
- Registry cleanup (with extensive safety)
- Service configuration optimization
- Startup entry management
- Scheduled task cleanup

**Rationale**: More comprehensive system maintenance capabilities.

**Requirement**: Each action must have extensive preview, validation, and rollback capabilities. These actions are higher risk than user-temp quarantine.

#### Remote Access (Explicitly Excluded)
- Remote API exposure
- Multi-machine management
- Centralized dashboard

**Rationale**: While technically interesting, remote access fundamentally changes the security model.

**Status**: Explicitly excluded from current plans. The local-first, localhost-only design is a core security principle.

---

## Design Principles for Future Development

1. **Local-first remains paramount**: All intelligence gathering stays on the local machine.
2. **Read-by-default**: Any new features default to read-only behavior.
3. **Explicit opt-in for modifications**: Remediation requires explicit user action.
4. **Safety scales with risk**: Higher-risk actions get more validation and rollback.
5. **Test coverage**: New features must include comprehensive tests.
6. **No premature optimization**: Keep the codebase simple and maintainable.

---

## Version Planning

No arbitrary dates or version numbers are committed to in advance. Development proceeds through milestones based on user needs and technical readiness.

Current version: **v0.15.1-alpha**

Next version will be determined when sufficient new functionality warrants a release.
