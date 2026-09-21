"""Phase 12.2 tests: health resource budgets."""

from __future__ import annotations

import json

import pytest

from app.health.budgets import DEFAULT_BUDGETS, HealthBudgets


class TestValidBudgets:
    def test_defaults_accepted(self):
        budgets = HealthBudgets()
        assert budgets.max_session_runtime_ms > 0
        assert budgets.max_stage_runtime_ms > 0
        assert budgets.max_history_runs > 0
        assert budgets.max_evidence_items > 0
        assert budgets.max_ai_context_items > 0

    def test_custom_valid_budgets(self):
        budgets = HealthBudgets(
            max_session_runtime_ms=60000,
            max_stage_runtime_ms=10000,
            max_history_runs=5,
            max_evidence_items=3,
            max_ai_context_items=5,
        )
        assert budgets.max_history_runs == 5

    def test_default_constant(self):
        assert DEFAULT_BUDGETS == HealthBudgets()


class TestInvalidBudgets:
    @pytest.mark.parametrize(
        "field",
        [
            "max_session_runtime_ms",
            "max_stage_runtime_ms",
            "max_history_runs",
            "max_evidence_items",
            "max_ai_context_items",
        ],
    )
    def test_zero_rejected(self, field):
        with pytest.raises(ValueError, match="positive int"):
            HealthBudgets(**{field: 0})

    @pytest.mark.parametrize(
        "field",
        [
            "max_session_runtime_ms",
            "max_stage_runtime_ms",
            "max_history_runs",
            "max_evidence_items",
            "max_ai_context_items",
        ],
    )
    def test_negative_rejected(self, field):
        with pytest.raises(ValueError, match="positive int"):
            HealthBudgets(**{field: -1})


class TestSerialization:
    def test_round_trip(self):
        budgets = HealthBudgets(max_history_runs=7)
        assert HealthBudgets.from_dict(budgets.to_dict()) == budgets

    def test_deterministic(self):
        budgets = HealthBudgets()
        first = json.dumps(budgets.to_dict(), sort_keys=True)
        second = json.dumps(
            HealthBudgets.from_dict(budgets.to_dict()).to_dict(),
            sort_keys=True,
        )
        assert first == second


class TestImmutability:
    def test_budgets_cannot_mutate(self):
        budgets = HealthBudgets()
        with pytest.raises(Exception):
            budgets.max_history_runs = 1  # type: ignore[misc]
