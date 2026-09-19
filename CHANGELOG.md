# Changelog

All notable changes to Old Computer Manager will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
