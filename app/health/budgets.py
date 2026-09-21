"""Health resource budgets (Phase 12.2).

Budgets declare *how much work is allowed*.  They contain no enforcement
logic; the runner consumes them (12.3).  All limits must be positive.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HealthBudgets:
    """Immutable resource limits for a health session."""

    max_session_runtime_ms: int = 300000
    max_stage_runtime_ms: int = 120000
    max_history_runs: int = 50
    max_evidence_items: int = 10
    max_ai_context_items: int = 30

    def __post_init__(self) -> None:
        for field_name in (
            "max_session_runtime_ms",
            "max_stage_runtime_ms",
            "max_history_runs",
            "max_evidence_items",
            "max_ai_context_items",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"Budget '{field_name}' must be a positive int")

    def to_dict(self) -> dict:
        """Deterministic serialization (fixed key order)."""
        return {
            "max_session_runtime_ms": self.max_session_runtime_ms,
            "max_stage_runtime_ms": self.max_stage_runtime_ms,
            "max_history_runs": self.max_history_runs,
            "max_evidence_items": self.max_evidence_items,
            "max_ai_context_items": self.max_ai_context_items,
        }

    @classmethod
    def from_dict(cls, data: dict) -> HealthBudgets:
        """Deserialize; raises ValueError on invalid limits."""
        return cls(
            max_session_runtime_ms=data.get("max_session_runtime_ms", 300000),
            max_stage_runtime_ms=data.get("max_stage_runtime_ms", 120000),
            max_history_runs=data.get("max_history_runs", 50),
            max_evidence_items=data.get("max_evidence_items", 10),
            max_ai_context_items=data.get("max_ai_context_items", 30),
        )


DEFAULT_BUDGETS = HealthBudgets()
