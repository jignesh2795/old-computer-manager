"""Historical metrics extraction from snapshots.

Defines which metrics are available and how to extract them.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MetricDefinition:
    """Definition of a trackable metric."""

    name: str
    category: str
    unit: str
    description: str
    extract_from: str  # 'dict_key', 'list_length', 'partition'


# All available metrics
METRIC_DEFINITIONS: dict[str, MetricDefinition] = {
    # Storage partition metrics (per-partition, extracted as storage_{device}_{metric})
    # These are dynamic - defined at extraction time based on actual partitions

    # Battery metrics
    "health_percent": MetricDefinition(
        name="health_percent",
        category="battery",
        unit="%",
        description="Battery health as percentage of design capacity",
        extract_from="dict_key",
    ),
    "full_charge_capacity_mwh": MetricDefinition(
        name="full_charge_capacity_mwh",
        category="battery",
        unit="mwh",
        description="Full charge capacity in milliwatt-hours",
        extract_from="dict_key",
    ),
    "wear_percent": MetricDefinition(
        name="wear_percent",
        category="battery",
        unit="%",
        description="Battery wear as percentage",
        extract_from="dict_key",
    ),

    # Hardware metrics
    "ram_total_bytes": MetricDefinition(
        name="ram_total_bytes",
        category="hardware",
        unit="bytes",
        description="Total physical RAM in bytes",
        extract_from="dict_key",
    ),
    "cpu_cores_physical": MetricDefinition(
        name="cpu_cores_physical",
        category="hardware",
        unit="count",
        description="Number of physical CPU cores",
        extract_from="dict_key",
    ),
    "cpu_cores_logical": MetricDefinition(
        name="cpu_cores_logical",
        category="hardware",
        unit="count",
        description="Number of logical CPU cores",
        extract_from="dict_key",
    ),

    # Count metrics
    "software_count": MetricDefinition(
        name="software_count",
        category="software",
        unit="count",
        description="Number of installed software items",
        extract_from="list_length",
    ),
    "startup_count": MetricDefinition(
        name="startup_count",
        category="startup",
        unit="count",
        description="Number of startup entries",
        extract_from="list_length",
    ),
    "services_count": MetricDefinition(
        name="services_count",
        category="services",
        unit="count",
        description="Number of services",
        extract_from="list_length",
    ),
    "scheduled_tasks_count": MetricDefinition(
        name="scheduled_tasks_count",
        category="scheduled_tasks",
        unit="count",
        description="Number of scheduled tasks",
        extract_from="list_length",
    ),
    "processes_count": MetricDefinition(
        name="processes_count",
        category="processes",
        unit="count",
        description="Number of running processes",
        extract_from="list_length",
    ),

    # Diagnostic metrics (from diagnostic_runs)
    "diagnostic_cpu_percent": MetricDefinition(
        name="diagnostic_cpu_percent",
        category="diagnostics",
        unit="%",
        description="CPU utilization from diagnostic snapshot",
        extract_from="dict_key",
    ),
    "diagnostic_memory_percent": MetricDefinition(
        name="diagnostic_memory_percent",
        category="diagnostics",
        unit="%",
        description="Memory utilization from diagnostic snapshot",
        extract_from="dict_key",
    ),
    "diagnostic_device_problem_count": MetricDefinition(
        name="diagnostic_device_problem_count",
        category="diagnostics",
        unit="count",
        description="Number of devices reporting problems",
        extract_from="dict_key",
    ),
}


def get_metric_definitions() -> dict[str, MetricDefinition]:
    """Return all defined metric definitions."""
    return dict(METRIC_DEFINITIONS)


def get_storage_metric_name(device: str, metric: str) -> str:
    """Generate a stable metric name for a storage partition.

    Uses the device path as the partition identity.
    """
    # Normalize device path for stable identity
    normalized = device.replace("\\", "/").lower().rstrip("/")
    return f"storage_{normalized}_{metric}"
