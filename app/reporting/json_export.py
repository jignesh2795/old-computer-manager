"""Deterministic JSON serialization for the unified health report."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from app.reporting.models import HealthReport


def _serialize(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, set):
        return sorted(obj)
    if isinstance(obj, tuple):
        return [_serialize(v) for v in obj]
    if isinstance(obj, list):
        return [_serialize(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    # dataclass-like objects
    if hasattr(obj, "__dataclass_fields__"):
        d: dict[str, Any] = {}
        for fname in obj.__dataclass_fields__:  # type: ignore[attr-defined]
            val = getattr(obj, fname)
            d[fname] = _serialize(val)
        return d
    return str(obj)


def report_to_dict(report: HealthReport) -> dict[str, Any]:
    """Convert a HealthReport to a plain dict suitable for JSON."""
    return _serialize(report)


def report_to_json(report: HealthReport, *, indent: int = 2, sort_keys: bool = False) -> str:
    """Serialize a HealthReport to a JSON string."""
    data = report_to_dict(report)
    return json.dumps(data, indent=indent, sort_keys=sort_keys, ensure_ascii=False)
