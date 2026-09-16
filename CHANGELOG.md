# Changelog

All notable changes to Old Computer Manager will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
