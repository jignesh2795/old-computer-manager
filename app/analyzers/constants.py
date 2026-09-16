"""Centralized thresholds and constants for analyzers."""

from __future__ import annotations

# -- Storage thresholds (percent_used) --
STORAGE_WARNING_THRESHOLD = 80
STORAGE_CRITICAL_THRESHOLD = 90

# -- Startup thresholds --
STARTUP_HIGH_COUNT = 10

# -- Process thresholds --
PROCESS_HIGH_CPU_PERCENT = 80.0
PROCESS_HIGH_MEMORY_FRACTION = 0.10  # 10% of physical RAM
PROCESS_TOP_N = 5  # max findings per category (CPU / memory)

# -- Service analysis --
# No thresholds currently. The existing snapshot fields (Name, DisplayName,
# State, StartMode, StartName, PathName) do not contain enough reliable
# information to establish anomalous conditions without domain-specific
# allowlists.  The analyzer documents this limitation and returns no findings.

# -- Scheduled-task analysis --
# No thresholds currently. The existing snapshot fields (TaskName, TaskPath,
# State, Author, Description) do not contain enough reliable information to
# distinguish normal disabled tasks from problematic ones.  The analyzer
# documents this limitation and returns no findings.

# -- Battery health thresholds (health_percent) --
# Informational only. Battery age, temperature, calibration, reporting
# accuracy, and chemistry affect interpretation.  A threshold does NOT
# prove the battery is unsafe.
BATTERY_HEALTH_GOOD_THRESHOLD = 80       # >= 80% : good
BATTERY_HEALTH_DEGRADED_THRESHOLD = 60   # >= 60% : degraded
                                        # < 60%  : critical
