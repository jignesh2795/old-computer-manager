"""Thresholds and constants for diagnostic analyzers."""

from __future__ import annotations

# ── Performance thresholds ──────────────────────────────────────────────
CPU_HIGH_PERCENT = 85.0
MEMORY_HIGH_PERCENT = 85.0

# ── Disk I/O rate thresholds (bytes/sec) ───────────────────────────────
# Only rate-based thresholds produce warnings. Cumulative totals are
# informational telemetry and do not produce warnings by themselves.
DISK_IO_HIGH_READ_BYTES_PER_SEC = 100 * 1024 * 1024   # 100 MB/s
DISK_IO_HIGH_WRITE_BYTES_PER_SEC = 100 * 1024 * 1024  # 100 MB/s

# ── Thermal thresholds (Celsius) ───────────────────────────────────────
CPU_TEMP_WARNING = 80
CPU_TEMP_CRITICAL = 95
DISK_TEMP_WARNING = 50
DISK_TEMP_CRITICAL = 60

# ── Limits ─────────────────────────────────────────────────────────────
MAX_DEVICES_RETURNED = 200
MAX_DIAGNOSTIC_RESULTS = 100
MAX_EVIDENCE_LENGTH = 2000
MAX_SUMMARY_LENGTH = 500

# ── PowerShell timeout ─────────────────────────────────────────────────
POWERSHELL_TIMEOUT_SECONDS = 20
