# Release Notes: v0.5.0-alpha

**Local Computer Intelligence Core**

Released: 2026-09-16

## Summary

Old Computer Manager v0.5.0-alpha is the first stable milestone — a complete local-first computer intelligence system for Windows with safe remediation capabilities.

## Major Capabilities

### Intelligence Gathering
- 11 read-only collectors (hardware, OS, storage, software, startup, services, tasks, processes, battery)
- SQLite knowledge base with discovery history
- 6 analysis engines with configurable thresholds
- File intelligence: large files, duplicates, type analysis

### Safe Remediation
- User temp quarantine with rollback (files never permanently deleted)
- Preview before execution
- Cryptographically bound confirmation tokens
- Full audit trail

### Unified Reporting
- Human-readable health report
- Deterministic JSON export
- Analysis status tracking

### Local API
- 8 read-only GET endpoints
- localhost-only binding
- Interactive Swagger/ReDoc documentation

## Test Results

```
397 passed
3 skipped
0 failures
```

## Safety Posture

- API is read-only, localhost-only
- No remote access
- No arbitrary shell execution
- No AI execution path
- Registry/services/tasks not modified
- Permanent deletion not used
- Battery serial numbers never stored

## Known Limitations

- Battery observation is non-baseline (hardware being replaced)
- Windows-only platform support
- No real-time monitoring
- No web UI
- No historical trend visualization

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# Run discovery
old-computer-manager discover

# Analyze results
old-computer-manager analyze

# Generate report
old-computer-manager report

# Start API
old-computer-manager serve
```

## Documentation

- [README](README.md) — Full documentation
- [CHANGELOG](CHANGELOG.md) — Version history
- [ROADMAP](ROADMAP.md) — Future directions
- [SECURITY](SECURITY.md) — Safety model

## License

Personal use and local computer management.
