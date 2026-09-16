# Security Model

This document describes the safety and security boundaries of Old Computer Manager v0.5.0-alpha.

## Core Security Principles

1. **Local-first**: All data stays on the local machine. No network calls for data collection or storage.
2. **Read-by-default**: Intelligence gathering never modifies the system.
3. **Explicit opt-in for modifications**: Any system changes require explicit user action.
4. **Defense in depth**: Multiple layers of validation prevent accidental or malicious harm.

## Safety Boundary

```text
Finding → Action → Preview → Explicit Confirmation → Validation → Controlled Executor → Audit/Rollback
```

### Layer 1: Finding

Analysis identifies an issue based on collected data. Findings are read-only observations.

### Layer 2: Action

A registered remediation action targets the issue. Actions are defined with:
- Risk level (low/medium/high/critical)
- Target scope
- Reversibility
- Parameter schema

### Layer 3: Preview

Before execution, users can preview exactly what would change. Previews:
- Produce no side effects
- Show affected files and their current state
- Display warnings and caveats
- Are read-only operations

### Layer 4: Explicit Confirmation

Execution requires a cryptographically bound confirmation token:
- Token is bound to the specific action ID
- Token is single-use (consumed after execution)
- Token uses SHA-256 hashing with a random secret
- Forged or wrong-action tokens are rejected

### Layer 5: Validation

Actions are validated before execution:
- Action must be registered in the registry
- Action must have valid parameters
- Finding must exist in the database
- Finding must belong to a completed analysis run
- No arbitrary command parameters allowed

### Layer 6: Controlled Executor

Execution is performed by a controlled executor:
- Only validated actions can execute
- Only registered actions can execute
- Arbitrary commands cannot be passed
- Execution results are recorded with success/failure status

### Layer 7: Audit/Rollback

All executions create audit records:
- Status transitions are tracked (proposed → executing → succeeded/failed)
- Failed transitions are rejected
- Quarantined files can be restored via rollback
- Audit trail persists in the database

## API Security

### Localhost Only

The FastAPI server binds to `127.0.0.1` by default:
- No remote network access
- No external API exposure
- No authentication required (localhost is trusted)

### Read-Only Endpoints

All API endpoints are GET-only:
- No POST, PUT, DELETE, or PATCH endpoints
- No modification capabilities
- No file system changes
- No database writes

### No Auto-Discovery

The API does not trigger discovery or analysis:
- Endpoints serve existing database data only
- No background processes are started
- No system state changes occur

## Remediation Safety

### Current Actions

#### User Temp Quarantine

The first and only real remediation action:

**What it does**:
- Moves temporary files from user TEMP directory to quarantine
- Files older than configured threshold (default: 7 days) are eligible
- Only targets per-user TEMP/TMP directories from `os.environ`

**What it does NOT do**:
- Never permanently deletes files
- Never targets system TEMP directories
- Never targets files outside user TEMP
- Never targets directories (only files)
- Never targets symlinks

**Safety properties**:
- Atomic file moves with collision detection
- Idempotent execution (safe to run multiple times)
- Full rollback capability
- Quarantine records stored in database
- Audit trail for all operations

### Demo Actions

Two no-op actions exist for testing:
- `demo.noop.print_message`: Simulates printing (no I/O)
- `demo.noop.report_status`: Simulates status check (no system calls)

## Privacy Protections

### Battery Serial Numbers

Battery serial numbers are intentionally excluded:
- Only boolean `serial_number_present` is recorded
- No hardware serial numbers are stored
- Manufacturer and model names are stored (non-sensitive)

### File Paths

File paths are stored as-is without modification:
- No obfuscation or encoding
- Paths are local filesystem paths only
- No network paths or URLs are collected

## Testing

### Security Tests

The test suite includes comprehensive security verification:

- **Dangerous path detection**: Tests verify no subprocess, os.system, registry, or shell execution
- **File deletion prevention**: Tests verify no os.remove or os.unlink calls
- **Service modification prevention**: Tests verify no Windows service changes
- **Privilege escalation prevention**: Tests verify no admin elevation
- **Confirmation forgery prevention**: Tests verify forged tokens are rejected
- **Validation bypass prevention**: Tests verify unvalidated actions are rejected

### Test Coverage

- 397 tests passing
- 3 skipped (symlink-related on Windows)
- 0 failures

## Known Limitations

### Current Scope

- Windows-only (collectors use WMI)
- No network security (API is localhost only)
- No encryption at rest (SQLite is plaintext)
- No authentication (localhost is trusted)

### Not Implemented

- No intrusion detection
- No audit log rotation
- No encrypted database
- No secure deletion

## Reporting Security Issues

This is a personal project for local computer management. Security issues should be reported to the project maintainer directly.

## Future Considerations

If remote access is ever added:
- TLS required for all connections
- Authentication required
- Rate limiting
- Audit logging for all requests
- Network isolation options

**Current status**: Remote access is explicitly excluded from current plans.
