"""Repository for historical database queries.

Provides methods to extract historical data from the existing SQLite database.
This module accesses the database but does not perform analysis.
"""

from __future__ import annotations

from typing import Any

from app.database.sqlite import SnapshotStore
from app.history.models import MetricObservation


# Categories that provide numeric metrics
NUMERIC_CATEGORIES = {"storage", "battery", "hardware"}
# Categories that provide counts
COUNT_CATEGORIES = {"software", "startup", "services", "scheduled_tasks", "processes"}


class HistoryRepository:
    """Read-only repository for historical data extraction."""

    def __init__(self, store: SnapshotStore) -> None:
        self._store = store

    def get_completed_runs(
        self, limit: int | None = None, since_id: int | None = None
    ) -> list[dict[str, Any]]:
        """Return completed discovery runs, newest first."""
        return self._store.get_completed_runs(limit=limit, since_id=since_id)

    def get_all_run_ids(self, limit: int | None = None) -> list[int]:
        """Return all completed run IDs, oldest first for time-series."""
        runs = self._store.get_completed_runs(limit=limit)
        return [r["id"] for r in reversed(runs)]

    def get_observations(
        self, run_ids: list[int], metric_name: str, category: str
    ) -> list[MetricObservation]:
        """Extract observations for a specific metric across runs.

        Args:
            run_ids: Run IDs to query (oldest first).
            metric_name: Name of the metric to extract.
            category: Snapshot category to look in.

        Returns:
            List of MetricObservation, one per valid run.
        """
        snapshots = self._store.get_snapshots_for_runs(run_ids, category)
        observations = []
        for snap in snapshots:
            payload = snap["payload"]

            # Handle storage metrics (list of partitions)
            if category == "storage" and isinstance(payload, list):
                for partition in payload:
                    device = partition.get("device") or partition.get("mountpoint", "unknown")
                    # Check if this partition matches the metric name
                    if metric_name.startswith(f"storage_{device}_"):
                        suffix = metric_name[len(f"storage_{device}_"):]
                        value = partition.get(suffix)
                        if value is not None:
                            try:
                                observations.append(
                                    MetricObservation(
                                        metric_name=metric_name,
                                        timestamp=snap["collected_at"],
                                        discovery_run_id=snap["run_id"],
                                        value=float(value),
                                        unit="%" if "percent" in suffix else "bytes",
                                        source=category,
                                    )
                                )
                            except (TypeError, ValueError):
                                pass
            else:
                # Direct key extraction (battery, hardware, etc.)
                value = self._extract_metric(payload, metric_name)
                if value is not None:
                    observations.append(
                        MetricObservation(
                            metric_name=metric_name,
                            timestamp=snap["collected_at"],
                            discovery_run_id=snap["run_id"],
                            value=value,
                            unit=self._get_unit(metric_name),
                            source=category,
                        )
                    )
        return observations

    def get_all_observations(
        self, run_ids: list[int]
    ) -> dict[str, list[MetricObservation]]:
        """Extract all available metrics across runs.

        Returns:
            Dict mapping metric_name to list of observations.
        """
        result: dict[str, list[MetricObservation]] = {}

        # Storage metrics
        storage_snaps = self._store.get_snapshots_for_runs(run_ids, "storage")
        for snap in storage_snaps:
            payload = snap["payload"]
            if isinstance(payload, list):
                for partition in payload:
                    device = partition.get("device") or partition.get("mountpoint", "unknown")
                    prefix = f"storage_{device}_"
                    for metric in ["percent_used", "free_bytes", "used_bytes"]:
                        value = partition.get(metric)
                        if value is not None:
                            name = prefix + metric
                            result.setdefault(name, []).append(
                                MetricObservation(
                                    metric_name=name,
                                    timestamp=snap["collected_at"],
                                    discovery_run_id=snap["run_id"],
                                    value=float(value),
                                    unit="%" if "percent" in metric else "bytes",
                                    source="storage",
                                )
                            )

        # Battery metrics
        battery_snaps = self._store.get_snapshots_for_runs(run_ids, "battery")
        for snap in battery_snaps:
            payload = snap["payload"]
            if isinstance(payload, dict):
                for metric in ["health_percent", "full_charge_capacity_mwh", "wear_percent"]:
                    value = payload.get(metric)
                    if value is not None:
                        result.setdefault(metric, []).append(
                            MetricObservation(
                                metric_name=metric,
                                timestamp=snap["collected_at"],
                                discovery_run_id=snap["run_id"],
                                value=float(value),
                                unit="%" if "percent" in metric else "mwh",
                                source="battery",
                            )
                        )

        # Hardware metrics
        hw_snaps = self._store.get_snapshots_for_runs(run_ids, "hardware")
        for snap in hw_snaps:
            payload = snap["payload"]
            if isinstance(payload, dict):
                for metric in ["ram_total_bytes", "cpu_cores_physical", "cpu_cores_logical"]:
                    value = payload.get(metric)
                    if value is not None:
                        result.setdefault(metric, []).append(
                            MetricObservation(
                                metric_name=metric,
                                timestamp=snap["collected_at"],
                                discovery_run_id=snap["run_id"],
                                value=float(value),
                                unit="bytes" if "bytes" in metric else "count",
                                source="hardware",
                            )
                        )

        # Count metrics (from lists)
        count_configs = [
            ("software", "software", lambda p: len(p) if isinstance(p, list) else None),
            ("startup", "startup", lambda p: len(p) if isinstance(p, list) else None),
            ("services", "services", lambda p: len(p) if isinstance(p, list) else None),
            ("scheduled_tasks", "scheduled_tasks", lambda p: len(p) if isinstance(p, list) else None),
            ("processes", "processes", lambda p: len(p) if isinstance(p, list) else None),
        ]
        for metric_name, category, extractor in count_configs:
            snaps = self._store.get_snapshots_for_runs(run_ids, category)
            for snap in snaps:
                value = extractor(snap["payload"])
                if value is not None:
                    result.setdefault(metric_name, []).append(
                        MetricObservation(
                            metric_name=metric_name,
                            timestamp=snap["collected_at"],
                            discovery_run_id=snap["run_id"],
                            value=float(value),
                            unit="count",
                            source=category,
                        )
                    )

        return result

    def get_findings_history(
        self, run_ids: list[int]
    ) -> list[dict[str, Any]]:
        """Return all findings across multiple runs."""
        return self._store.get_findings_for_runs(run_ids)

    def _extract_metric(self, payload: Any, metric_name: str) -> float | None:
        """Extract a numeric metric from a snapshot payload."""
        if isinstance(payload, dict):
            value = payload.get(metric_name)
            if value is not None:
                try:
                    return float(value)
                except (TypeError, ValueError):
                    return None
        return None

    def _get_unit(self, metric_name: str) -> str:
        """Return the unit for a metric name."""
        if "percent" in metric_name:
            return "%"
        if "bytes" in metric_name:
            return "bytes"
        if "capacity" in metric_name:
            return "mwh"
        return "count"
