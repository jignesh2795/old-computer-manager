# Changelog

All notable changes to Old Computer Manager will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] - Phase 11B — Candidate Preview Intelligence

### Phase 11B — Candidate Preview Intelligence

This phase adds safe, deterministic, read-only preview generation for action candidates. A preview explains exactly what WOULD happen if an action were executed, without performing any modification.

#### New Module
- `app/remediation/preview.py`: Preview, PreviewBuilder, PreviewItem, PreviewStatus, PreviewSummary models + build_preview() convenience function

#### Preview Features
- `PreviewStatus`: READY, STALE, INSUFFICIENT_EVIDENCE, BLOCKED, UNAVAILABLE, ERROR
- `Preview` dataclass (frozen): 25+ fields including affected_items, expected_effect, rollback_description, fingerprint
- `PreviewBuilder`: Deterministic builder, no LLM, no executor, no confirmation tokens
- Available candidate preview: full target list with paths, sizes, counts, bytes
- Proposed candidate preview: design-only, non-executable, clear limitations
- Blocked candidate preview: explains why action cannot execute
- Insufficient evidence preview: identifies missing evidence
- Stale evidence preview: refuses to present expired targets
- `MAX_PREVIEW_ITEMS = 20` for bounded output
- `PreviewItem` fingerprint for change detection

#### API
- `GET /api/v1/remediation/candidates/{candidate_id}/preview`: Read-only preview for a candidate

#### CLI
- `ocm actions preview-candidate <candidate_id> [--json]`: Preview a candidate

#### Security
- Preview has NO executor import, NO confirmation token import, NO rollback execution
- Preview does NOT create execution audit records
- Preview is informational only, never an authorization token
- Preview is frozen (immutable)
- No subprocess/shell in preview module

#### Tests
- 45 new Phase 11B tests covering model, builder, API, CLI, security, determinism
- 873 backend tests passing (828 existing + 45 new), 8 skipped
- 13 frontend tests passing

## [v0.13.0-alpha] - 2026-09-20

### Phase 11A — Action Candidate System (Diagnostic-to-Action Intelligence)

This phase introduces the ActionCandidate model and PolicyEngine that evaluates diagnostic data against the action catalog to produce deterministic, evidence-based action candidates. The system is strictly read-only — `executable` is always `False`, and no execution authority is granted by the candidate subsystem.

#### New Modules
- `app/remediation/candidates.py`: ActionCandidate, CandidateStatus, EvidenceSource, EvidenceSourceType, CandidatesSummary models
- `app/remediation/policy.py`: Policy engine with PolicyContext, evaluate_candidates(), Rule A (disk.cleanup_temp), Rule B (user_temp_quarantine), blocked/proposed candidate builders, MAX_ACTION_CANDIDATES=20, MAX_EVIDENCE_ITEMS=10

#### API
- `GET /api/v1/remediation/candidates`: List action candidates with optional `?status=` and `?action_id=` filters
- `GET /api/v1/remediation/candidates/{candidate_id}`: Get candidate detail by ID

#### CLI
- `ocm actions candidates [--json] [--status X] [--action X]`: List action candidates

#### AI Integration
- AI prompt v1.3 with 11 new candidate rules (25-35)
- `action_candidates_summary` field on AIContext for AI visibility
- AI cannot promote or demote candidate status

#### Reporting
- ActionCandidateSummary in HealthReport
- action_candidates field in report output

#### Constraints
- `executable` property always returns `False`
- Policy engine has no import of executor module
- No subprocess or shell=True in candidates.py or policy.py
- Historical evidence alone cannot create immediate cleanup targets
- Blocked actions never become available candidates

#### Tests
- 62 new Phase 11A tests covering models, policy engine, API, CLI, security, integration
- 828 backend tests passing (766 existing + 62 new), 8 skipped
- 13 frontend tests passing
- Security audit: no executor/subprocess/shell imports in candidates.py or policy.py

## [v0.12.0-alpha] - 2026-09-20

### Phase 10B + 10B.1 — Useful Diagnostics Expansion + Quality Hardening

This release adds 5 new read-only diagnostic modules (event_log, reliability, boot_timing, network_health, driver_consistency) expanding the diagnostic system to 10 modules total. Also adds `collection_time_ms` on every DiagnosticResult for regression detection, WMI query consolidation for older hardware, and network adapter status via psutil.

#### New Diagnostic Modules
- `app/diagnostics/event_log.py`: Bounded event log collection (max 200 events, 30-day lookback), grouped by source, recurring error detection
- `app/diagnostics/reliability.py`: Crash-history diagnostics via single Win32_ReliabilityRecord query (summary, app failures, update failures)
- `app/diagnostics/boot_timing.py`: Last boot time, uptime, startup program count via psutil + registry
- `app/diagnostics/network_health.py`: Adapter status (psutil, zero PowerShell), DNS configuration, DNS resolution test
- `app/diagnostics/driver_consistency.py`: Driver age and error checks via single Win32_PnPEntity query

#### Quality Hardening (10B.1)
- `collection_time_ms` field on DiagnosticResult for per-result timing
- `total_time_ms` field on DiagnosticRun for overall run timing
- Reliability module: 3 WMI queries consolidated to 1
- Driver consistency: 2 WMI queries consolidated to 1
- Network adapter status: switched from PowerShell to psutil (zero overhead)
- Database schema migration for collection_time_ms column
- API responses include collection_time_ms

#### Added
- 5 new diagnostic categories in DiagnosticCategory enum: EVENT_LOG, RELIABILITY, BOOT_TIMING, NETWORK_HEALTH, DRIVER_CONSISTENCY
- New constants: EVENT_LOG_MAX_EVENTS, EVENT_LOG_LOOKBACK_DAYS, EVENT_LOG_ERROR_WARN_THRESHOLD, EVENT_LOG_RECURRING_THRESHOLD, RELIABILITY_MAX_EVENTS, RELIABILITY_LOOKBACK_DAYS, RELIABILITY_CRASH_WARN_THRESHOLD, BOOT_SLOW_SECONDS, DRIVER_AGE_WARN_DAYS, DRIVER_MAX_RETURNED, NETWORK_DNS_TIMEOUT
- 5 new GET-only API endpoints: /diagnostics/event-log, /diagnostics/reliability, /diagnostics/boot-timing, /diagnostics/network-health, /diagnostics/driver-consistency
- 25 new regression tests for all Phase 10B categories
- DiagnosticRun properties: event_log_results, reliability_results, boot_timing_results, network_health_results, driver_consistency_results

#### Tests
- 766 backend tests passing, 8 skipped
- 13 frontend tests passing
- Observed ~15s total diagnostic runtime on HP Pavilion 15-ab023tx

---

## [v0.11.0-alpha] - 2026-09-19

### Phase 10A + 10A.1 — Read-Only Advanced Diagnostics + Quality Hardening

This release adds 5 read-only diagnostic modules (disk health, thermal, performance, devices, Windows health) that inspect system state without modification. Each module runs independently with per-module failure isolation. Also adds 6 new GET-only API endpoints, CLI `diagnostics` command, dashboard Diagnostics section, and comprehensive test suite.

#### Quality Hardening (10A.1)
- Fixed memory diagnostic: `psutil.swap_memory()` failure no longer hides working `virtual_memory()` data. Memory now correctly reports as available when only swap is disabled (common on corporate Windows with disabled performance counters).
- Fixed disk I/O semantics: cumulative bytes since boot are informational telemetry, not diagnostic warnings. Rate is measured via 1-second interval sampling. Only rate exceeding 100 MB/s produces a warning.
- Snapshot-vs-trend wording reviewed: CPU and memory summaries read as snapshots ("utilization", "used"), not long-term conditions.
- 8 new regression tests covering memory swap failure, disk I/O rate semantics, and snapshot wording.

### Added

#### Diagnostic Modules
- `app/diagnostics/__init__.py`: Package exports
- `app/diagnostics/models.py`: `DiagnosticResult`, `DiagnosticRun`, `DiagnosticStatus` (ok/warning/critical/unavailable/not_supported/failed), `DiagnosticCategory` (disk/thermal/performance/devices/windows)
- `app/diagnostics/constants.py`: All thresholds centralized (CPU_HIGH_PERCENT=85, MEMORY_HIGH_PERCENT=85, DISK_IO_HIGH_READ_BYTES_PER_SEC=100MB/s, DISK_IO_HIGH_WRITE_BYTES_PER_SEC=100MB/s, CPU_TEMP_WARNING=80, CPU_TEMP_CRITICAL=95)
- `app/diagnostics/_powershell.py`: Shared PowerShell helper (subprocess, timeout=20s, read-only)
- `app/diagnostics/disk.py`: Disk health via Win32_DiskDrive/MSFT_PhysicalDisk (SMART status, predictive failure, temperature)
- `app/diagnostics/thermal.py`: Thermal via psutil + MSAcpi_ThermalZoneTemperature (WMI Kelvin→Celsius conversion)
- `app/diagnostics/performance.py`: CPU/memory/disk I/O/network I/O snapshot via psutil with rate-based I/O measurement
- `app/diagnostics/devices.py`: Device/driver diagnostics via Win32_PnPEntity (ConfigManagerErrorCode problem detection)
- `app/diagnostics/windows_health.py`: Windows health via Win32_OperatingSystem, reboot-required registry check, uptime, Win32_ReliabilityRecord
- `app/diagnostics/analyzers.py`: Diagnostic→Finding conversion (conservative, observation-based)
- `app/diagnostics/runner.py`: `run_diagnostics()` orchestrator with per-module isolation, `save_diagnostic_run()` persistence

#### Database Integration
- `diagnostic_runs` and `diagnostic_results` tables with indexes
- Methods: `save_diagnostic_run()`, `get_latest_diagnostic_run()`, `load_diagnostic_results()`, `get_diagnostic_results_by_category()`, `get_diagnostic_summary()`

#### Reporting Integration
- `DiagnosticsSummary` model in `app/reporting/models.py`
- `_build_diagnostics_summary()` in `app/reporting/builder.py`
- `HealthReport.diagnostics` field

#### AI Context Integration
- `diagnostics_summary` field in `AIContext`
- `_build_diagnostics_summary()` in `app/ai/context.py`
- `MAX_DIAGNOSTIC_RESULTS = 20`

#### History Integration
- `diagnostic_cpu_percent`, `diagnostic_memory_percent`, `diagnostic_device_problem_count` metrics

#### API Endpoints (6 new GET-only)
- `GET /api/v1/diagnostics/summary` — Diagnostic run summary
- `GET /api/v1/diagnostics/disk` — Disk health diagnostics
- `GET /api/v1/diagnostics/thermal` — Thermal diagnostics
- `GET /api/v1/diagnostics/performance` — Performance diagnostics
- `GET /api/v1/diagnostics/devices` — Device/driver diagnostics
- `GET /api/v1/diagnostics/windows` — Windows health diagnostics

#### CLI Command
- `old-computer-manager diagnostics [--json] [category]` with optional category filter

#### Dashboard
- `Diagnostics.tsx` component with per-category results display
- Integrated into `App.tsx` with diagnosticsSummary fetch

#### Tests
- `tests/test_diagnostics.py`: 76+ tests covering models, parsing, SMART unavailable, predictive failure, thermal, performance, CPU/memory thresholds, disk I/O rate, device problems, Windows health, failure isolation, persistence, history, report, API, CLI, dashboard, AI context, security invariants, analyzers, runner, constants, data quality, PowerShell helper, memory swap failure, disk I/O cumulative vs rate, snapshot wording
- **Backend**: 741 passed, 8 skipped, 0 failures
- **Frontend**: 13 passed, 0 failures

### Changed
- `app/database/sqlite.py`: Added diagnostic tables and 6 new methods
- `app/reporting/models.py`: Added DiagnosticsSummary model, HealthReport.diagnostics field
- `app/reporting/builder.py`: Added `_build_diagnostics_summary()`
- `app/ai/context.py`: Added diagnostics_summary field, `_build_diagnostics_summary()`, `MAX_DIAGNOSTIC_RESULTS`
- `app/history/metrics.py`: Added 3 diagnostic metric definitions
- `app/api/schemas.py`: Added DiagnosticResultResponse, DiagnosticsSummaryResponse
- `app/api/routes.py`: Added 6 diagnostics endpoints + `_get_diagnostic_results()` helper
- `app/cli.py`: Added `cmd_diagnostics()` + diagnostics subcommand parser
- `frontend/src/types/api.ts`: Added diagnostic types
- `frontend/src/api/client.ts`: Added 7 diagnostics API methods
- `frontend/src/App.tsx`: Integrated Diagnostics component

### Safety
- All diagnostic modules are read-only (no system modification)
- Per-module failure isolation — failure in one never aborts others
- DiagnosticStatus distinguishes unavailable from hardware problem
- No SMART health claims when platform doesn't expose it
- No temperature inference from CPU load
- No subjective performance scores
- No causes invented — observation ≠ diagnosis
- All thresholds centralized in constants.py
- Subprocess only for PowerShell read-only commands (no shell=True, timeout=20s)
- 6 new GET-only endpoints (no POST/execute/repair)
- No new file writes, registry modifications, or system changes
- Cumulative disk I/O is informational telemetry, not diagnostic signal
- Rate-based disk I/O warnings only when measured rate exceeds threshold

---

## [v0.10.0-alpha] - 2026-09-19

### Phase 10A — Read-Only Advanced Diagnostics Foundation

This release adds 5 read-only diagnostic modules (disk health, thermal, performance, devices, Windows health) that inspect system state without modification. Each module runs independently with per-module failure isolation. Also adds 6 new GET-only API endpoints, CLI `diagnostics` command, dashboard Diagnostics section, and comprehensive test suite.

### Added

#### Diagnostic Modules (Phase 10A)
- `app/diagnostics/__init__.py`: Package exports
- `app/diagnostics/models.py`: `DiagnosticResult`, `DiagnosticRun`, `DiagnosticStatus` (ok/warning/critical/unavailable/not_supported/failed), `DiagnosticCategory` (disk/thermal/performance/devices/windows)
- `app/diagnostics/constants.py`: All thresholds centralized (CPU_HIGH_PERCENT=85, MEMORY_HIGH_PERCENT=85, CPU_TEMP_WARNING=80, CPU_TEMP_CRITICAL=95, etc.)
- `app/diagnostics/_powershell.py`: Shared PowerShell helper (subprocess, timeout=20s, read-only)
- `app/diagnostics/disk.py`: Disk health via Win32_DiskDrive/MSFT_PhysicalDisk (SMART status, predictive failure, temperature)
- `app/diagnostics/thermal.py`: Thermal via psutil + MSAcpi_ThermalZoneTemperature (WMI Kelvin→Celsius conversion)
- `app/diagnostics/performance.py`: CPU/memory/disk I/O/network I/O snapshot via psutil
- `app/diagnostics/devices.py`: Device/driver diagnostics via Win32_PnPEntity (ConfigManagerErrorCode problem detection)
- `app/diagnostics/windows_health.py`: Windows health via Win32_OperatingSystem, reboot-required registry check, uptime, Win32_ReliabilityRecord
- `app/diagnostics/analyzers.py`: Diagnostic→Finding conversion (conservative, observation-based)
- `app/diagnostics/runner.py`: `run_diagnostics()` orchestrator with per-module isolation, `save_diagnostic_run()` persistence

#### Database Integration
- `diagnostic_runs` and `diagnostic_results` tables with indexes
- Methods: `save_diagnostic_run()`, `get_latest_diagnostic_run()`, `load_diagnostic_results()`, `get_diagnostic_results_by_category()`, `get_diagnostic_summary()`

#### Reporting Integration
- `DiagnosticsSummary` model in `app/reporting/models.py`
- `_build_diagnostics_summary()` in `app/reporting/builder.py`
- `HealthReport.diagnostics` field

#### AI Context Integration
- `diagnostics_summary` field in `AIContext`
- `_build_diagnostics_summary()` in `app/ai/context.py`
- `MAX_DIAGNOSTIC_RESULTS = 20`

#### History Integration
- `diagnostic_cpu_percent`, `diagnostic_memory_percent`, `diagnostic_device_problem_count` metrics

#### API Endpoints (6 new GET-only)
- `GET /api/v1/diagnostics/summary` — Diagnostic run summary
- `GET /api/v1/diagnostics/disk` — Disk health diagnostics
- `GET /api/v1/diagnostics/thermal` — Thermal diagnostics
- `GET /api/v1/diagnostics/performance` — Performance diagnostics
- `GET /api/v1/diagnostics/devices` — Device/driver diagnostics
- `GET /api/v1/diagnostics/windows` — Windows health diagnostics

#### CLI Command
- `old-computer-manager diagnostics [--json] [category]` with optional category filter

#### Dashboard
- `Diagnostics.tsx` component with per-category results display
- Integrated into `App.tsx` with diagnosticsSummary fetch

#### Tests
- `tests/test_diagnostics.py`: 68+ new tests covering models, parsing, SMART unavailable, predictive failure, thermal, performance, CPU/memory thresholds, disk I/O, device problems, Windows health, failure isolation, persistence, history, report, API, CLI, dashboard, AI context, security invariants, analyzers, runner, constants, data quality, PowerShell helper
- **Backend**: 733 passed, 8 skipped, 0 failures
- **Frontend**: 13 passed, 0 failures

### Changed
- `app/database/sqlite.py`: Added diagnostic tables and 6 new methods
- `app/reporting/models.py`: Added DiagnosticsSummary model, HealthReport.diagnostics field
- `app/reporting/builder.py`: Added `_build_diagnostics_summary()`
- `app/ai/context.py`: Added diagnostics_summary field, `_build_diagnostics_summary()`, `MAX_DIAGNOSTIC_RESULTS`
- `app/history/metrics.py`: Added 3 diagnostic metric definitions
- `app/api/schemas.py`: Added DiagnosticResultResponse, DiagnosticsSummaryResponse
- `app/api/routes.py`: Added 6 diagnostics endpoints + `_get_diagnostic_results()` helper
- `app/cli.py`: Added `cmd_diagnostics()` + diagnostics subcommand parser
- `frontend/src/types/api.ts`: Added diagnostic types
- `frontend/src/api/client.ts`: Added 7 diagnostics API methods
- `frontend/src/App.tsx`: Integrated Diagnostics component

### Safety
- All diagnostic modules are read-only (no system modification)
- Per-module failure isolation — failure in one never aborts others
- DiagnosticStatus distinguishes unavailable from hardware problem
- No SMART health claims when platform doesn't expose it
- No temperature inference from CPU load
- No subjective performance scores
- No causes invented — observation ≠ diagnosis
- All thresholds centralized in constants.py
- Subprocess only for PowerShell read-only commands (no shell=True, timeout=20s)
- 6 new GET-only endpoints (no POST/execute/repair)
- No new file writes, registry modifications, or system changes

---

## [v0.10.0-alpha] - 2026-09-19

### Phase 9B — Safe Temp Cleanup (`disk.cleanup_temp`)

This release implements the `disk.cleanup_temp` remediation action — a policy-driven cleanup of the current user's approved TEMP directory. Files are moved to quarantine (NEVER permanently deleted) with full rollback capability. Also fixes API response models to expose all remediation action metadata fields.

### Added

#### Safe Temp Cleanup (Phase 9B)
- `app/remediation/cleanup_temp.py`: Policy layer with `preview_cleanup()`, `execute_cleanup()`, `validate_age_days()`
- `disk.cleanup_temp` moved from PROPOSED → IMPLEMENTED in the action catalog
- Registered with `ParameterSchema(age_days)` — only parameter, values 7–365, reject zero/negative/non-integer
- Age policy: default 30 days, min 7, max 365
- `MAX_FILES_PER_EXECUTION = 500`; excess candidates skipped with structured result
- Move-only operation via `shutil.move` through quarantine (FORBIDDEN: os.remove, os.unlink, shutil.rmtree)
- Revalidation immediately before moving each file
- Full safety chain: Registered → Preview → Confirmation → Validation → Executor → Audit
- Idempotent: running twice does not duplicate quarantine records
- Only scans current user's approved TEMP directory (`TEMP`/`TMP` env vars)
- Path containment: `is_under_directory()` validates source paths

#### API Field Exposure Fix
- `GET /api/v1/remediation/actions` now returns all action metadata fields (implementation_status, blast_radius, rollback_category, eligibility, category, action_version)
- Both dedicated endpoint and `/api/v1/report` remediation section now expose complete metadata

### Changed
- `app/remediation/catalog.py`: `disk.cleanup_temp` moved from PROPOSED to IMPLEMENTED
- `app/remediation/registry.py`: Registered `disk.cleanup_temp` with `ParameterSchema`
- `app/remediation/preview.py`: Added `disk.cleanup_temp` preview handling with `CleanupPreview`
- `app/remediation/executor.py`: Added `_execute_cleanup_temp()` on `QuarantineExecutor`
- `app/remediation/__init__.py`: Added cleanup_temp exports
- `app/reporting/builder.py`: `_build_remediation_summary()` recognizes `disk.cleanup_temp` in `_REAL_ACTIONS`
- `app/cli.py`: Fixed CLI preview for `CleanupPreview` compatibility
- `app/api/routes.py`: Fixed remediation response to include all metadata fields

### Tests
- Created `tests/test_cleanup_temp.py`: 66 tests across 30+ categories (A-AI)
- Updated `tests/test_remediation_catalog.py`: Adjusted for new IMPLEMENTED counts
- **Backend**: 665 passed, 6 skipped, 0 failures
- **Frontend**: 13 passed, 0 failures

### Safety
- Only `shutil.move` used for file operations (no delete, no rmtree)
- `is_under_directory()` path containment for all operations
- Revalidation immediately before each file move
- MAX_FILES_PER_EXECUTION enforced; excess skipped
- Age parameter validated (7–365, integer only)
- No new dangerous imports, shell/subprocess/registry access
- No execution endpoints; existing GET-only API unchanged

---

## [v0.9.1-alpha] - 2026-09-18

### Phase 9A — Remediation Action Framework Expansion

This release expands the remediation framework with structured metadata for action lifecycle, risk, eligibility, blast radius, rollback design, and dependencies. No new real remediation actions are implemented — only `user_temp_quarantine` remains as the sole production action. All proposed/blocked/not_implemented actions remain non-executable. All implemented actions require explicit human confirmation through the controlled remediation workflow.

### Added

#### Remediation Action Model (Phase 9A)
- `ImplementationStatus` enum: implemented, proposed, blocked, not_implemented
- `BlastRadius` enum: single_file, user_directory, user_profile, system_wide, bootloader
- `RollbackCategory` enum: shutil_move_restore, registry_restore, service_restore, startup_restore, snapshot_restore, not_applicable
- `EligibilityStatus` enum: eligible, blocked, requires_design_review, requires_privilege_review, requires_rollback_design
- `RemediationAction` extended with 7 new fields: implementation_status, blast_radius, rollback_category, dependencies, eligibility, action_version, category (backward compatible defaults)
- Action dependencies: tuple of action_ids this action depends on
- Explicit human confirmation: all implemented actions require confirmation tokens through the controlled remediation workflow

#### Action Catalog (Phase 9A)
- `app/remediation/catalog.py`: Structured catalog of all known remediation actions
- 13 catalog entries: 1 production implemented, 2 demo/test, 6 blocked, 4 proposed
- `validate_catalog_consistency()` enforces invariants (blocked not eligible, demos categorized)
- `get_production_entries()` returns only non-demo actions

#### Action Eligibility Gate (Phase 9A)
- `app/remediation/eligibility.py`: Single decision point for action eligibility
- `check_eligibility(action_id)` returns EligibilityResult with status and reason
- `is_action_allowed(action_id)` quick check for execution eligibility
- `get_blocked_actions()`, `get_proposed_actions()`, `get_implemented_production_actions()`

#### Registry Validation (Phase 9A)
- `ActionRegistry.validate_against_catalog()` checks all registered actions match catalog metadata

#### Audit Schema (Phase 9A)
- `AuditRecord` extended with `action_version` and `implementation_status` fields
- `AUDIT_TABLE` schema includes new columns
- Backward-compatible migration: existing databases automatically get new columns

#### AI Advisory (Phase 9A)
- AI prompt v1.2 with REMEDIATION ACTION RULES (rules 8-14)
- AI distinguishes implemented vs proposed vs blocked actions
- AI never recommends blocked or not_implemented actions
- AI context includes implementation_status, blast_radius, rollback_category, eligibility

#### API (Phase 9A)
- `RemediationActionResponse` extended with implementation_status, blast_radius, rollback_category, eligibility, category, action_version

#### Frontend (Phase 9A)
- Remediation dashboard filters out demo/test actions
- Shows implementation status tags (Implemented/Proposed/Blocked/Not Implemented)
- Shows production action count separately from total registered count
- Shows blast radius metadata

#### Tests (Phase 9A)
- 56 new tests covering catalog, eligibility, action model, registry validation, audit migration, and security invariants
- Total: 598 backend tests passing, 13 frontend tests passing

---

## [v0.9.0-alpha] - 2026-09-16

### Phase 8B — Historical AI Reasoning

This release extends the AI advisory system to explain historical changes, trends, recurring findings, baselines, and anomalies using factual/inference/uncertainty distinction.

### Added

#### Historical AI Reasoning (Phase 8B)
- AI system prompt v1.1 with historical reasoning rules
- FACT/INFERENCE/UNCERTAINTY distinction in historical explanations
- Trend observations: increasing, decreasing, stable metrics with evidence
- Baseline reasoning: current vs. baseline comparison with delta and direction
- Recurring finding explanations with occurrence count and time span
- Anomaly interpretation: describe changes without speculative cause attribution
- Battery baseline reasoning with unavailable/established/degraded status
- Data quality awareness in historical context

#### AI Models
- `HistoricalSummary` dataclass with bounded historical analysis summary
- `AIAdvisory.historical_summary` field (backward compatible, optional)
- `AdvisoryMetadata.prompt_version` updated to "1.1"

#### API
- `AdvisoryHistoricalSummaryResponse` schema in API responses
- `AdvisoryResponse.historical_summary` field (nullable, backward compatible)

#### Frontend
- `AdvisoryHistoricalSummaryResponse` TypeScript type
- Historical summary display in AI Advisory dashboard section

#### Tests
- 44 new tests covering historical AI reasoning (A-R test cases)
- Historical context inclusion, limits, baseline, trend, recurring, anomaly reasoning
- Factual/inference distinction verification
- CLI, JSON, API, and dashboard output verification
- Safety and security validation

### Changed
- AI prompt version: 1.0 -> 1.1
- AI advisory now includes historical observations when data available
- MockProvider generates historical observations from context
- CLI `ai` command displays historical summary section
- API endpoint returns historical_summary in advisory response

### Safety
- All AI recommendations remain executable=false
- No new modification authority
- No subprocess, shell, registry, or network calls
- Historical observations are factual, not speculative
- Prompt explicitly distinguishes FACT from INTERPRETATION from UNCERTAINTY

### Test Baseline
- **Backend**: 542 passed, 3 skipped, 0 failures
- **Frontend**: 13 passed, 0 failures

---

## [v0.8.0-alpha] - 2026-09-16

### Phase 8A — Historical Trends + Baseline Comparison

This release adds historical analysis capabilities for tracking system changes over time.

### Added

#### Historical Analysis (Phase 8A)
- `app/history/` package with models, repository, metrics, trends, anomalies, baseline, and runner
- Trend calculation with configurable thresholds (increasing, decreasing, stable, insufficient_data)
- Baseline comparison with battery-specific rules (degradation threshold, health establishment)
- Recurring findings detection across multiple discovery runs
- Simple anomaly detection (sudden storage increase, battery health drop, startup/software count changes)
- 14 trackable metrics across storage, battery, hardware, and count categories
- Partition identity via normalized device paths
- Run selection (completed runs only, last N, since ID)
- Data quality tracking (valid, missing, not_supported, failed)

#### API Endpoints
- `GET /api/v1/history/summary` — Full historical analysis summary
- `GET /api/v1/history/trends` — Trend analysis for all metrics
- `GET /api/v1/history/baseline` — Baseline comparison for all metrics
- `GET /api/v1/history/anomalies` — Detected anomalies

#### CLI Commands
- `old-computer-manager history` — Human-readable historical analysis
- `old-computer-manager history --json` — JSON output
- `--limit` — Maximum runs to consider
- `--metric` — Filter to specific metric

#### Dashboard
- Historical section showing trends, baselines, recurring findings, and anomalies

#### AI Context
- Extended AI context builder with bounded historical summaries
- Battery baseline awareness for advisory generation

### Safety
- All endpoints are GET-only (read-only)
- No new modification authority
- No subprocess, shell, registry, or network calls
- No new database schema changes (uses existing tables)
- 47 new tests covering all historical analysis features

### Test Baseline
- **Backend**: 498 passed, 3 skipped, 0 failures
- **Frontend**: 13 passed, 0 failures

---

## [v0.7.0-alpha] - 2026-09-16

### Phase 7A — Lightweight Local Dashboard

This release adds a local read-only web dashboard for visualizing system data.

### Added

#### Dashboard (Phase 7A)
- `frontend/` directory with Vite + React + TypeScript setup
- Dashboard components: Overview, Findings, Storage, Battery, FileAnalysis, AiAdvisory, Remediation, System
- TypeScript types matching existing FastAPI API schemas
- API service layer consuming existing read-only endpoints
- Manual Refresh button (no continuous polling)
- Compact card-based layout designed for older computers
- Status visualization: normal, warning, critical, not available, not analyzed
- Progress bars for storage utilization
- Findings display with severity, title, message, evidence, recommendation
- AI Advisory section showing observations, recommendations, uncertainties, limitations
- Remediation metadata display (informational only, no execution controls)
- Graceful error handling for API failures, missing data, analysis not run
- Production build configuration
- 13 frontend tests covering all dashboard sections

#### Safety
- Dashboard is read-only (no POST/PUT/PATCH/DELETE endpoints)
- No execution controls (Apply/Execute/Delete/Cleanup buttons)
- No filesystem access from frontend
- No shell execution
- No external telemetry or analytics
- Localhost-only API connection
- TypeScript types enforce read-only contract

### Test Baseline
- **Backend**: 451 passed, 3 skipped, 0 failures
- **Frontend**: 13 passed, 0 failures

---

## [v0.6.0-alpha] - 2026-09-16

### Phase 6A — Local-First AI Advisory Layer

This release adds AI advisory capabilities while maintaining strict safety boundaries.

### Added

#### AI Advisory (Phase 6A)
- `app/ai/` package with models, context builder, provider abstraction, and advisory generation
- Deterministic mock provider for tests (no API quotas consumed)
- Context builder with explicit budget limits (MAX_FINDINGS, MAX_LARGE_FILES, etc.)
- Safety validator detecting prohibited content (shell commands, registry edits, etc.)
- Prompt design with factuality rules and version tracking
- Frozen dataclass models: AIAdvisory, Observation, Recommendation, Uncertainty, Limitation
- Recommendation model enforces `executable=False` always
- CLI `ai` command with human-readable and JSON output
- FastAPI `GET /api/v1/ai/advisory` endpoint (read-only, mock provider)
- 54 comprehensive tests covering safety, context limits, provider abstraction, and more

#### Safety
- AI has no executor dependency (verified by architecture tests)
- AI cannot execute remediation, modify files, or change system state
- Context excludes secrets, battery serial numbers, and file contents
- External provider disabled by default (requires explicit environment configuration)
- All AI output validated for prohibited content before return

### Test Baseline
- **451 passed**
- **3 skipped** (symlink-related on Windows)
- **0 failures**

---

## [v0.5.0-alpha] - 2026-09-16

### Initial Stable Milestone — Local Computer Intelligence Core

This release represents the complete local-first computer intelligence system with safe remediation capabilities.

### Added

#### Discovery (Phase 1)
- 11 read-only collectors: hardware, storage, Windows OS, BIOS, computer system, software, startup, services, scheduled tasks, processes, battery
- `CollectorResult` frozen dataclass with status tracking
- SQLite knowledge base with foreign key enforcement
- Discovery history across multiple runs

#### Analysis (Phase 2)
- 6 analyzer framework: storage, startup, process, service, task, battery
- Configurable thresholds for warnings and critical findings
- Analysis runner with error handling and status tracking
- Findings stored with severity, evidence, and recommendations

#### Remediation Safety (Phase 3A)
- `RemediationAction` frozen dataclass with risk level validation
- Action registry with schema validation
- Preview capability (no side effects)
- Confirmation tokens with cryptographic binding (SHA-256)
- Single-use token consumption
- Controlled executor with validation requirements
- Audit trail with state machine lifecycle
- Rollback framework (currently not implemented for demo actions)

#### User Temp Quarantine (Phase 3B)
- First real remediation action
- Moves files from user TEMP directory to quarantine
- Age threshold configuration (default: 7 days)
- Quarantine store with rollback records
- Idempotent execution
- Atomic file moves with collision handling
- 53 security tests including dangerous path detection

#### Battery Deep Inspection (Phase 3C)
- WMI enrichment for battery capacity data
- Health calculation: >=80% good, >=60% degraded, <60% critical
- Cycle count tracking (when available)
- Serial number intentionally excluded (privacy)
- 28 collector tests + 17 analyzer tests

#### File/Storage Intelligence (Phase 4)
- Recursive directory scanner with exclusion rules
- System critical path protection (System32, WinSxS, Program Files, etc.)
- Symlink detection and exclusion
- Large file ranking with configurable thresholds
- File type grouping by extension
- Duplicate detection: size pre-filter → chunk signature → SHA-256
- Scan statistics with incremental updates
- 45 comprehensive tests (A-X coverage)

#### Unified Report (Phase 5A)
- `HealthReport` model with all system sections
- Human-readable formatter with sections and summaries
- Deterministic JSON export with sorted keys
- Schema version tracking (currently "1.0")
- Analysis status tracking (not_run/completed/failed/partial)
- 48 report tests + 19 regression tests

#### Local FastAPI API (Phase 5B)
- 8 read-only GET endpoints
- localhost-only binding (127.0.0.1)
- Interactive Swagger/ReDoc documentation
- Pydantic response models
- Query parameter filtering for findings
- 47 API tests including security verification

### Test Baseline

- **397 passed**
- **3 skipped** (symlink-related tests on Windows)
- **0 failures**

### Dependencies

- `psutil>=6.0,<7` — System monitoring
- `fastapi>=0.100.0,<1` — API framework
- `uvicorn[standard]>=0.23.0,<1` — ASGI server

### Known Limitations

- Battery observation is non-baseline (hardware being replaced)
- Windows-only platform support
- No real-time monitoring or daemon
- No AI advisory layer
- No web UI
- File analysis limited to local filesystem
- Quarantine limited to user TEMP directory

---

## Previous Development History

### Phase 1 — Discovery (v0.1-alpha)
- Initial collectors and SQLite storage
- CLI discover command

### Phase 2 — Analysis
- Analyzer framework and 6 analyzers
- CLI analyze command

### Phase 3A — Remediation Safety
- Safety framework with validation, confirmation, execution
- Audit trail and state machine

### Phase 3B — User Temp Quarantine
- First real remediation action
- Rollback capability
- 53 security tests

### Phase 3C — Battery Inspection
- WMI battery enrichment
- Health analysis thresholds
- Privacy-preserving (no serial numbers)

### Phase 4 — File/Storage Intelligence
- Directory scanner with exclusions
- Large file and duplicate detection
- File type analysis

### Phase 5A — Unified Report
- HealthReport builder
- Human and JSON formatters
- Analysis status tracking

### Phase 5B — Local API
- FastAPI server with read-only endpoints
- Dependency injection with test isolation
- Security verification tests
