# Release Notes: v0.6.0-alpha

**AI Advisory Layer**

Released: 2026-09-16

## Summary

Old Computer Manager v0.6.0-alpha adds a local-first AI advisory layer with strict safety boundaries. The AI can analyze system state and provide observations/recommendations but has no executor access, no confirmation-token access, and no system modification authority.

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

### AI Advisory (NEW)
- Read-only advisory generation from system state
- Deterministic mock provider (no API quotas consumed)
- Context builder with explicit budget limits
- Safety validator detecting prohibited content
- Structured output: observations, recommendations, uncertainties, limitations
- CLI `ai` command with human-readable and JSON output
- FastAPI `GET /api/v1/ai/advisory` endpoint

### Unified Reporting
- Human-readable health report
- Deterministic JSON export
- Analysis status tracking

### Local API
- 9 read-only GET endpoints
- localhost-only binding
- Interactive Swagger/ReDoc documentation

## Test Results

```
451 passed
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
- AI has no executor access
- AI has no confirmation-token access
- AI has no rollback access
- AI output validated for prohibited content
- External AI provider disabled by default

## Known Limitations

- Battery observation is non-baseline (hardware being replaced)
- Windows-only platform support
- No real-time monitoring
- No web UI
- No historical trend visualization
- AI advisory uses mock provider (no real LLM integration)

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

# Get AI advisory
old-computer-manager ai

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
