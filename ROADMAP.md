# Roadmap

This document tracks completed milestones and potential future directions for Old Computer Manager.

## Completed Milestones

### v0.9.1-alpha — Remediation Action Framework Expansion ✓

**Status**: 2026-09-18 (unreleased)

**Capabilities**:
- Structured action catalog with risk model, eligibility, blast radius, rollback categories
- Eligibility gate: single decision point for action execution eligibility
- Action model extended with implementation_status, blast_radius, rollback_category, dependencies, eligibility, action_version, category
- Registry validates against catalog (consistency check)
- Audit trail persists action_version and implementation_status
- AI prompt v1.2 with remediation action rules (distinguish implemented/proposed/blocked)
- Frontend filters demo/test actions, shows implementation status
- Only `user_temp_quarantine` is the production remediation action
- 56 new tests, 598 total backend tests, 13 frontend tests

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
- Browser cache cleanup (user temp scope)
- Download folder duplicate removal
- Old log file quarantine
- Windows Update cleanup

**Rationale**: Extend the safe remediation framework with more user-temp-scoped actions that follow the same safety model.

#### Historical Trend Analysis
- Disk usage trends over time
- Process resource patterns
- Battery degradation tracking
- Software installation history

**Rationale**: The discovery history is already stored; visualization and trend analysis would add value.

#### Cross-Machine Comparison
- Compare hardware configurations
- Software inventory differences
- Performance baseline comparisons

**Rationale**: Useful for users managing multiple older computers.

### Medium-Term Candidates

#### AI Advisory Layer
- Intelligent recommendations based on collected data
- Natural language explanations of findings
- Priority-based remediation suggestions
- Context-aware optimization advice

**Rationale**: AI can provide personalized guidance after reliable evidence has been collected and structured.

**Requirement**: Must maintain local-first principle. AI processing should be optional and clearly separated from core intelligence gathering.

#### React Dashboard
- Interactive web UI for data visualization
- Historical trend charts
- Remediation workflow interface
- System health dashboard

**Rationale**: Visual interface makes the intelligence more accessible and actionable.

**Requirement**: Must work with existing API layer. No server-side rendering that requires network access.

#### Monitoring Daemon
- Background process for continuous observation
- Resource spike detection
- Boot time tracking
- Network event monitoring

**Rationale**: Real-time monitoring complements point-in-time discovery.

**Requirement**: Must be opt-in with clear resource usage disclosure.

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

Current version: **v0.6.0-alpha**

Next version will be determined when sufficient new functionality warrants a release.
