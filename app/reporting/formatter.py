"""Human-readable formatter for the unified health report."""

from __future__ import annotations

from app.reporting.models import HealthReport


def _bytes_human(n: int | None) -> str:
    if n is None:
        return "N/A"
    if n == 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def format_report(report: HealthReport) -> str:
    lines: list[str] = []
    w = lines.append

    w("OLD COMPUTER MANAGER")
    w("=" * 60)
    w(f"Schema version:  {report.schema_version}")
    w(f"Generated at:    {report.generated_at}")
    w(f"Discovery run:   #{report.discovery_run_id or 'N/A'} ({report.discovery_status or 'N/A'})")
    w("")

    # System
    w("SYSTEM")
    w("-" * 60)
    s = report.system
    if s.hostname:
        w(f"  Hostname:     {s.hostname}")
    if s.os_name:
        w(f"  OS:           {s.os_name} {s.os_version or ''}".rstrip())
    if s.architecture:
        w(f"  Architecture: {s.architecture}")
    if s.manufacturer or s.model:
        w(f"  Machine:      {s.manufacturer or '?'} {s.model or ''}".rstrip())
    if s.bios_vendor or s.bios_version:
        w(f"  BIOS:         {s.bios_vendor or '?'} {s.bios_version or ''}".rstrip())
    if s.cpu_name:
        w(f"  CPU:          {s.cpu_name}")
    if s.cpu_cores_physical or s.cpu_cores_logical:
        w(f"  CPU cores:    {s.cpu_cores_physical or '?'} physical, {s.cpu_cores_logical or '?'} logical")
    if s.ram_total_bytes:
        w(f"  RAM:          {_bytes_human(s.ram_total_bytes)}")
    w("")

    # Storage
    w("STORAGE")
    w("-" * 60)
    st = report.storage
    if st.count == 0:
        w("  No partitions detected.")
    else:
        w(f"  Partitions: {st.count}")
        if st.total_capacity_bytes:
            w(f"  Total capacity: {_bytes_human(st.total_capacity_bytes)}")
        if st.total_free_bytes:
            w(f"  Total free:     {_bytes_human(st.total_free_bytes)}")
        for p in st.partitions:
            pct = f"{p.usage_percent:.1f}%" if p.usage_percent is not None else "?"
            w(f"  [{p.status or 'unknown':>8}] {p.device or '?':>8}  {p.filesystem or '?':>8}  "
              f"{_bytes_human(p.total_bytes):>10} total  {pct:>6} used")
    w("")

    # Battery
    w("BATTERY")
    w("-" * 60)
    b = report.battery
    if b.available is None:
        w("  Battery data not available.")
    elif not b.available:
        w("  No battery detected.")
    else:
        w(f"  Available:     Yes")
        w(f"  Status:        {b.status or 'N/A'}")
        w(f"  Charge:        {b.charge_percent if b.charge_percent is not None else 'N/A'}%")
        w(f"  Plugged in:    {b.plugged_in if b.plugged_in is not None else 'N/A'}")
        if b.design_capacity_mwh:
            w(f"  Design:        {_bytes_human(b.design_capacity_mwh * 1000)}")
        if b.full_charge_capacity_mwh:
            w(f"  Full charge:   {_bytes_human(b.full_charge_capacity_mwh * 1000)}")
        if b.health_percent is not None:
            w(f"  Health:        {b.health_percent:.1f}%")
        if b.wear_percent is not None:
            w(f"  Wear:          {b.wear_percent:.1f}%")
        if b.health_status:
            w(f"  Health status: {b.health_status}")
        if b.cycle_count is not None:
            w(f"  Cycle count:   {b.cycle_count}")
        if b.manufacturer:
            w(f"  Manufacturer:  {b.manufacturer}")
        if b.battery_name:
            w(f"  Name:          {b.battery_name}")
        w(f"  Baseline:      {b.baseline_status}")
    w("")

    # Findings
    w("FINDINGS")
    w("-" * 60)
    status = report.analysis_status
    if status == "not_run" or status is None:
        w("  Analysis: NOT RUN")
        w("  Findings: not analyzed")
    elif status == "failed":
        w("  Analysis: FAILED")
        w("  Findings: not available (analysis failed)")
    elif status in ("completed", "partial"):
        fg = report.findings
        total = fg.critical_count + fg.warning_count + fg.info_count
        label = "COMPLETED" if status == "completed" else "PARTIAL (some analyzers failed)"
        w(f"  Analysis: {label}")
        if report.findings_count is not None:
            w(f"  Findings: {report.findings_count}")
        else:
            w(f"  Findings: {total}")
        w(f"  Summary:  critical={fg.critical_count}, warning={fg.warning_count}, info={fg.info_count}")
        for sev_label, items in [("CRITICAL", fg.critical), ("WARNING", fg.warning), ("INFO", fg.info)]:
            if items:
                w(f"\n  {sev_label}:")
                for f in items[:20]:
                    w(f"    - [{f.analyzer}] {f.title}")
    else:
        w(f"  Analysis: {status or 'unknown'}")
        w("  Findings: status unknown")
    w("")

    # Software
    w("SOFTWARE")
    w("-" * 60)
    w(f"  Installed software count: {report.software.count}")
    w("")

    # Startup
    w("STARTUP")
    w("-" * 60)
    w(f"  Startup entries: {report.startup.count}")
    w("")

    # Processes
    w("PROCESSES")
    w("-" * 60)
    w(f"  Process count: {report.processes.count}")
    w("")

    # Services
    w("SERVICES")
    w("-" * 60)
    w(f"  Service count: {report.services.count}")
    w("")

    # Scheduled Tasks
    w("SCHEDULED TASKS")
    w("-" * 60)
    w(f"  Task count: {report.scheduled_tasks.count}")
    w("")

    # File Analysis
    w("FILE ANALYSIS")
    w("-" * 60)
    fa = report.file_analysis
    if not fa.available:
        w("  No file analysis scan available.")
    else:
        w(f"  Scan root: {fa.scan_root or 'N/A'}")
        w(f"  Scan time: {fa.scan_timestamp or 'N/A'}")
        w(f"  Files examined:     {fa.files_examined}")
        w(f"  Directories:        {fa.directories_examined}")
        w(f"  Bytes examined:     {_bytes_human(fa.bytes_examined)}")
        w(f"  Files skipped:      {fa.files_skipped}")
        w(f"  Symlinks skipped:   {fa.symlinks_skipped}")
        w(f"  Excluded items:     {fa.excluded_items}")
        w(f"  Inaccessible:       {fa.inaccessible_items}")
        w(f"  Duplicate groups:   {fa.duplicate_groups}")
        w(f"  Potential savings:  {_bytes_human(fa.potential_duplicate_bytes)}")
        if fa.largest_files:
            w("  Largest files:")
            for lf in fa.largest_files[:5]:
                w(f"    - {_bytes_human(lf.get('size_bytes'))}  {lf.get('path', '?')}")
    w("")

    # Remediation
    w("REMEDIATION CAPABILITIES")
    w("-" * 60)
    for a in report.remediation.actions:
        flags = []
        if a.reversible:
            flags.append("reversible")
        if a.requires_admin:
            flags.append("admin")
        if a.preview_available:
            flags.append("preview")
        if a.rollback_available:
            flags.append("rollback")
        w(f"  {a.action_id:<30} risk={a.risk_level:<10} [{', '.join(flags) or 'none'}]")
    w("")

    # Errors
    if report.errors:
        w("ERRORS")
        w("-" * 60)
        for e in report.errors:
            w(f"  [{e.severity}] {e.component}/{e.stage}: {e.message}")
        w("")

    return "\n".join(lines)
