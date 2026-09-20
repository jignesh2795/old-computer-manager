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

# ── Event log limits ───────────────────────────────────────────────────
EVENT_LOG_MAX_EVENTS = 200
EVENT_LOG_LOOKBACK_DAYS = 30
EVENT_LOG_ERROR_WARN_THRESHOLD = 10
EVENT_LOG_RECURRING_THRESHOLD = 3

# ── Reliability limits ─────────────────────────────────────────────────
RELIABILITY_MAX_EVENTS = 50
RELIABILITY_LOOKBACK_DAYS = 30
RELIABILITY_CRASH_WARN_THRESHOLD = 3

# ── Boot timing ────────────────────────────────────────────────────────
BOOT_SLOW_SECONDS = 120

# ── Network health ─────────────────────────────────────────────────────
NETWORK_DNS_TEST_TIMEOUT = 5

# ── Driver consistency ────────────────────────────────────────────────
DRIVER_AGE_WARN_DAYS = 365
DRIVER_MAX_RETURNED = 50

# ── Limits ─────────────────────────────────────────────────────────────
MAX_DEVICES_RETURNED = 200
MAX_DIAGNOSTIC_RESULTS = 100
MAX_EVIDENCE_LENGTH = 2000
MAX_SUMMARY_LENGTH = 500

# ── PowerShell timeout ─────────────────────────────────────────────────
POWERSHELL_TIMEOUT_SECONDS = 20
