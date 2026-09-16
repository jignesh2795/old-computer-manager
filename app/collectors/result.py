"""Standardized collector result type."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CollectorResult:
    """Result returned by every collector.

    Attributes:
        payload: The collected data (dict, list, or other JSON-serializable value).
        status: One of 'ok', 'empty', 'not_supported', 'failed'.
        error_message: Human-readable error description, only set when status is 'failed'.
    """

    payload: Any = None
    status: str = "ok"
    error_message: str | None = None
