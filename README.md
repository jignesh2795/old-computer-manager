# Old Computer Manager

A local-first, read-only-first computer intelligence and management system for understanding, diagnosing, preserving, and safely maintaining an older Windows computer.

## Project goals

- Discover hardware, Windows configuration, storage, software, startup mechanisms, services, scheduled tasks, processes, and network events.
- Build a historical local knowledge base of the computer.
- Analyze files, dates, duplicates, backup generations, and project history.
- Diagnose boot and resource spikes, including processes that start after network connectivity.
- Prepare safe Windows reset and migration plans.
- Assess dual-boot readiness before making partition or boot changes.
- Use AI only after reliable evidence has been collected and structured.

## Safety principles

1. v0.1 is read-only.
2. No automatic deletion, moving, disabling, partitioning, or Windows configuration changes.
3. Expensive scans are incremental and resource-aware.
4. Recommendations must cite evidence and confidence.
5. Future modifications require explicit approval, backup/quarantine where appropriate, verification, and an audit trail.

## Initial milestone: v0.1-alpha

The first milestone collects:

- Hardware and firmware information
- Windows version/build and boot information
- Physical disks, partitions, and logical drives
- Installed software
- Startup entries
- Services and scheduled tasks
- Process/resource observations
- Network events
- Initial file inventory
- A local SQLite database and baseline report

## Architecture

```text
Collectors -> SQLite knowledge base -> Analyzers -> Reports/UI -> AI (later)
```

The data model is intended to remain OS-neutral so macOS-specific collectors can be added later.
