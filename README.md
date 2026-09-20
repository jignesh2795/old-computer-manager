# Old Computer Manager

A local-first, read-only computer intelligence system for understanding, diagnosing, preserving, and safely maintaining older Windows computers.

## Version

**v0.14.0-alpha** — Candidate Preview Intelligence

## Purpose

Old Computer Manager collects hardware, software, and system configuration data from a local Windows machine, stores it in a SQLite knowledge base, and provides analysis and reporting capabilities. The system is designed for safe, read-only intelligence gathering with optional reversible remediation.

## Design Principles

1. **Local-first**: All data stays on the local machine. No network calls, no cloud services.
2. **Read-only by default**: Discovery and analysis never modify the system.
3. **Safe remediation**: Any modifications require explicit confirmation, validation, and provide rollback capability.
4. **Privacy-aware**: Battery serial numbers are never stored. User temp quarantine only targets per-user TEMP directories.
5. **Incremental**: History is preserved across multiple discovery runs for trend analysis.

## Supported Platforms

- Windows 10 (tested)
- Windows 11 (expected compatible)
- Python 3.11+

## Architecture

```text
Collectors -> SQLite Knowledge Base -> Analyzers -> Reports/API -> (Future: AI/UI)
```

### Components

| Layer | Description |
|-------|-------------|
| **Collectors** | 11 read-only data collectors (hardware, OS, storage, software, startup, services, tasks, processes, battery, Windows-specific) |
| **Analyzers** | 6 analysis engines (storage, startup, process, service, task, battery) that evaluate collected data against thresholds |
| **Diagnostics** | 10 read-only diagnostic modules (disk health, thermal, performance, devices, Windows health, event_log, reliability, boot_timing, network_health, driver_consistency) with per-module isolation |
| **SQLite Database** | Persistent knowledge base storing discovery snapshots, analysis findings, diagnostic runs, file scans, quarantine records, and audit trail |
| **File Analysis** | Directory scanner with large file detection, file type grouping, and duplicate detection |
| **Reporting** | Unified health report builder with human-readable and deterministic JSON export |
| **API** | Local read-only FastAPI server for programmatic access |
| **Remediation** | Safety framework with validation, confirmation tokens, controlled execution, and rollback |
| **Action Candidates** | Diagnostic-to-action intelligence: deterministic candidate evaluation, evidence binding, policy engine |
| **Dashboard** | Lightweight React frontend for local visualization (read-only) |

## CLI Commands

### Discovery

```bash
old-computer-manager discover
```

Runs all 11 collectors and saves results to `data/computer.db`. Returns hardware, Windows configuration, storage, software, startup entries, services, scheduled tasks, processes, and battery information.

### Analysis

```bash
old-computer-manager analyze
```

Analyzes the latest completed discovery run. Evaluates storage usage, startup entries, process resource usage, and battery health against configured thresholds. Saves findings to the database.

### File Intelligence

```bash
old-computer-manager files scan <path>
old-computer-manager files large [path]
old-computer-manager files types [path]
old-computer-manager files duplicates [path]
```

- **scan**: Full directory scan with large file detection, type grouping, and duplicate detection
- **large**: Show largest files (default: >100MB)
- **types**: File type breakdown by extension
- **duplicates**: Exact duplicate detection using size pre-filtering and SHA-256 hashing

### Reporting

```bash
old-computer-manager report
old-computer-manager report --json
```

Generates a unified health report from the latest completed discovery and analysis run. The `--json` flag outputs deterministic JSON suitable for programmatic consumption.

### API Server

```bash
old-computer-manager serve
old-computer-manager serve --host 127.0.0.1 --port 8000
```

Starts a local FastAPI server with read-only endpoints. Binds to localhost only by default.

### AI Advisory

```bash
old-computer-manager ai
old-computer-manager ai --json
```

Generates a local-first AI advisory from the latest completed report. The AI provides observations, recommendations, and uncertainties based on factual evidence. When historical data is available, the AI explains trends, baselines, recurring findings, and anomalies using factual/inference/uncertainty distinction.

**Important**: The AI advisory is read-only. It does NOT execute remediation, modify the system, or access secrets.

### Historical Analysis

```bash
old-computer-manager history
old-computer-manager history --json
old-computer-manager history --limit 20
old-computer-manager history --metric storage_C:\_percent_used
```

Analyzes historical trends across multiple discovery runs. Shows:
- **Trends**: Increasing, decreasing, or stable metrics over time
- **Baseline**: Comparison against earliest valid observation
- **Recurring findings**: Findings that appear across multiple runs
- **Anomalies**: Sudden changes (storage increase, battery health drop, etc.)

**Important**: This is descriptive historical analysis, not predictive failure forecasting.

### Remediation Actions

```bash
old-computer-manager actions
old-computer-manager actions preview <action_id>
old-computer-manager actions execute <action_id>
old-computer-manager actions rollback <record_id>
old-computer-manager actions candidates [--json] [--status X] [--action X]
old-computer-manager actions preview-candidate <candidate_id> [--json]
```

- **actions**: List registered remediation actions
- **preview**: Show what an action would do without executing
- **execute**: Execute an action with validation and confirmation
- **rollback**: Restore a quarantined file to its original location
- **candidates**: List action candidates (read-only, no execution authority)
- **preview-candidate**: Preview an action candidate (read-only, no execution authority)

### Advanced Diagnostics

```bash
old-computer-manager diagnostics
old-computer-manager diagnostics --json
old-computer-manager diagnostics disk
old-computer-manager diagnostics thermal
old-computer-manager diagnostics performance
old-computer-manager diagnostics devices
old-computer-manager diagnostics windows
```

Read-only diagnostic modules that inspect disk health, thermal sensors, CPU/memory/disk I/O/network performance, device/driver problems, and Windows system health (uptime, reboot status, reliability events). Each module runs independently — a failure in one never aborts others.

### Web Dashboard

```bash
# Start backend API server
old-computer-manager serve

# Start frontend development server
cd frontend
npm install
npm run dev
```

The dashboard provides a lightweight, read-only web interface for visualizing system data:

- **Overview**: System model, OS, CPU, RAM, storage summary, battery status
- **Findings**: Critical/warning/info analysis results with clear not-run vs completed states
- **Storage**: Partition usage with progress visualization
- **Battery**: Charge, health, wear, cycle count when available
- **AI Advisory**: Observations, recommendations, uncertainties, limitations, historical summary
- **Remediation**: Registered actions metadata (informational only, no execution controls)
- **Historical**: Trends, baselines, recurring findings, anomalies across runs

The dashboard consumes the existing FastAPI API and does not access SQLite directly.

**Important**: The dashboard is read-only. It contains NO Apply/Execute/Delete/Cleanup buttons.

## API Endpoints

All endpoints are GET-only and read-only. The server binds to localhost only.

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check (does not run discovery) |
| `GET /api/v1/report` | Full unified health report |
| `GET /api/v1/findings?severity=&analyzer=` | Analysis findings with optional filtering |
| `GET /api/v1/storage` | Storage summary with partition details |
| `GET /api/v1/battery` | Battery status (serial number never exposed) |
| `GET /api/v1/file-analysis` | Latest file scan summary |
| `GET /api/v1/remediation/actions` | Remediation action metadata only |
| `GET /api/v1/system` | System information |
| `GET /api/v1/ai/advisory` | AI advisory (read-only, uses mock provider) |
| `GET /api/v1/history/summary` | Historical analysis with trends, baselines, anomalies |
| `GET /api/v1/history/trends` | Trend analysis for all metrics |
| `GET /api/v1/history/baseline` | Baseline comparison for all metrics |
| `GET /api/v1/history/anomalies` | Detected anomalies in historical data |
| `GET /api/v1/diagnostics/summary` | Diagnostic run summary (all categories) |
| `GET /api/v1/diagnostics/disk` | Disk health diagnostics |
| `GET /api/v1/diagnostics/thermal` | Thermal diagnostics |
| `GET /api/v1/diagnostics/performance` | Performance diagnostics |
| `GET /api/v1/diagnostics/devices` | Device/driver diagnostics |
| `GET /api/v1/diagnostics/windows` | Windows health diagnostics |
| `GET /api/v1/remediation/candidates` | Action candidates (available/proposed/blocked/insufficient_evidence/stale) |
| `GET /api/v1/remediation/candidates/{candidate_id}` | Action candidate detail |
| `GET /api/v1/remediation/candidates/{candidate_id}/preview` | Action candidate preview (read-only) |

### Interactive Documentation

When the server is running, visit:
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

## Safety Model

### Read-Only Intelligence

- Discovery collectors never modify system state
- Analysis evaluates data without changes
- File scanning is read-only
- API serves existing database data only
- No automatic remediation is triggered by intelligence gathering

### AI Advisory Safety

The AI advisory layer is strictly read-only:

- **No execution**: AI cannot execute remediation actions
- **No modification**: AI cannot modify the system, registry, services, or files
- **No secrets**: AI context excludes passwords, tokens, API keys, and battery serial numbers
- **No network**: Default provider is local mock; external providers disabled by default
- **Factuality**: AI must distinguish measured facts from inference
- **Uncertainties**: AI explicitly lists missing information
- **Validation**: AI output is validated for prohibited content (shell commands, registry edits, etc.)

The AI's role is: UNDERSTAND -> EXPLAIN -> PRIORITIZE FACTUAL FINDINGS -> SUGGEST SAFE NEXT STEPS

#### Advisory vs Remediation

The AI advisory is **informatory only**. It provides observations and recommendations but does NOT:
- Execute remediation actions
- Call the executor
- Confirm actions
- Rollback changes
- Delete or move files
- Modify Windows registry, services, or startup

Users must manually review AI recommendations and use the remediation system (with confirmation tokens) to take action.

#### Provider Architecture

- **MockProvider** (default): Deterministic, no API quotas consumed, no network calls
- **ExternalProvider** (disabled by default): Requires explicit `AI_API_KEY` and `AI_API_URL` environment variables

#### Context Limits

AI context is bounded to prevent excessive data exposure:
- Max 20 findings
- Max 10 large files
- Max 5 duplicate groups
- Max 20 processes
- Max 15 startup items
- Text truncated to 500 characters

#### Privacy

- Battery serial numbers excluded (only boolean `serial_number_present`)
- File contents excluded (only metadata)
- Secrets never included in context

### Historical Analysis

The historical analysis system tracks how the computer changes across multiple discovery runs.

#### Trend Semantics

- **increasing**: Metric has increased beyond the stability threshold
- **decreasing**: Metric has decreased beyond the stability threshold
- **stable**: Change is within the stability threshold
- **insufficient_data**: Not enough observations to determine trend

#### Baseline Semantics

- **unavailable**: No valid baseline observation exists
- **established**: Baseline exists but no comparison yet
- **improved**: Current value is better than baseline
- **degraded**: Current value is worse than baseline (exceeds threshold)
- **unchanged**: Change is within the threshold
- **insufficient_data**: Cannot determine comparison

#### Battery Baseline Rule

Battery health baseline requires valid health_percent data. A dead battery (0% health) does not establish a baseline. The baseline is only established once:
- design capacity exists
- full-charge capacity exists
- health_percent is calculable

#### Recurring Findings

Findings that appear across multiple discovery runs are tracked with:
- First seen / last seen timestamps
- Occurrence count (number of runs)
- Run IDs where the finding appeared

#### Anomaly Limitations

Anomaly detection is simple and explainable:
- Sudden storage increase (>10 percentage points between runs)
- Sudden battery health drop (>10 percentage points between runs)
- Unusual startup/software count changes (>50% / >20% relative change)

This is **not** machine learning anomaly detection. It describes measured changes without speculative causal claims.

### Available Remediation

Currently implemented: **User Temp Quarantine**

This action moves temporary files older than a configurable threshold (default: 7 days) from the user's TEMP directory to an application-managed quarantine directory. Files are never permanently deleted.

### Safety Boundary

```text
Finding → Action → Preview → Explicit Confirmation → Validation → Controlled Executor → Audit/Rollback
```

1. **Finding**: Analysis identifies an issue
2. **Action**: Registered remediation action targets the issue
3. **Preview**: User sees exactly what would change
4. **Explicit Confirmation**: Cryptographically bound confirmation token required
5. **Validation**: Action validated against registry and database state
6. **Controlled Executor**: Execution with atomic operations and error handling
7. **Audit/Rollback**: Full audit trail and rollback capability

### Safety Guarantees

- API is read-only, localhost-only
- No remote API exposure
- No arbitrary shell execution
- No AI execution path
- Registry, services, and task configuration are not modified
- Permanent deletion is not part of user-temp quarantine
- Quarantine is reversible via rollback
- Administrator elevation is not required for current remediation actions
- Battery serial numbers are never stored

## Privacy Behavior

- Battery serial numbers are intentionally excluded from collection
- Only boolean `serial_number_present` is recorded
- User temp quarantine only targets per-user TEMP/TMP directories from `os.environ`
- No system temp directories are accessed
- File paths are stored as-is without modification

## Database Schema

The SQLite database (`data/computer.db`) stores:

- **Discovery runs**: Timestamps, status, collector results
- **Snapshots**: Hardware, OS, storage, software, startup, services, tasks, processes, battery
- **Analysis findings**: Severity, analyzer, evidence, recommendations
- **File scans**: Root path, stats, large files, type groups, duplicate groups
- **Quarantine records**: Original paths, quarantine paths, restore status
- **Audit trail**: Action lifecycle, status transitions, timestamps

Foreign key enforcement is enabled via `PRAGMA foreign_keys = ON`.

## Known Limitations

### Battery Baseline

The current machine's battery observation is **non-baseline** because the physical battery is dead and being replaced. The 0% charge and missing health data reflect this hardware state, not a software defect.

#### Post-Replacement Baseline Procedure

1. Install replacement battery
2. Boot Windows normally
3. Run `old-computer-manager discover`
4. Run `old-computer-manager analyze`
5. Run `old-computer-manager report`
6. Record observed values:
   - `design_capacity_mwh`
   - `full_charge_capacity_mwh`
   - `remaining_capacity_mwh`
   - `health_percent`
   - `wear_percent`
   - `cycle_count`
   - Charging status

Do not consider the baseline established until these steps are actually performed.

### Other Limitations

- Windows-only (collectors use WMI and Windows-specific APIs)
- No real-time monitoring or daemon mode
- No historical trend visualization
- No cross-machine comparison
- File analysis limited to local filesystem
- Duplicate detection requires files to be readable
- Quarantine limited to user TEMP directory only

## Future Directions

These features are **not implemented** and exist only as potential directions:

- Monitoring daemon for continuous observation
- Additional remediation actions
- Broader platform support (macOS, Linux)
- Advanced historical trend analysis
- Remote access (explicitly excluded for security)

## Development

### Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

### Running Tests

```bash
# Python backend tests
pytest tests/ -v

# Frontend tests
cd frontend
npm test
```

Current baseline:
- **Backend**: 741 passed, 8 skipped, 0 failures
- **Frontend**: 13 passed, 0 failures

### Project Structure

```text
app/
  __init__.py
  cli.py                    # Command-line interface
  discovery.py              # Discovery runner
  collectors/               # 11 data collectors
  analyzers/                # 6 analysis engines
  diagnostics/              # 5 read-only diagnostic modules (disk, thermal, performance, devices, windows)
  database/                 # SQLite knowledge base
  file_analysis/            # Directory scanner and analyzers
  remediation/              # Safety framework and quarantine
  reporting/                # Report builder and formatter
  api/                      # FastAPI server
  ai/                       # AI advisory layer
  history/                  # Historical trend analysis
frontend/
  src/                      # React TypeScript source
    components/             # Dashboard components
    types/                  # TypeScript type definitions
    api/                    # API client layer
  dist/                     # Production build output
tests/                      # Comprehensive test suite
data/                       # SQLite database (runtime)
```

## License

This project is for personal use and local computer management.
