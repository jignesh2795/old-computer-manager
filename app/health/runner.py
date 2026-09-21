"""Health session runner (Phase 12.3).

Orchestrates assessment stages with isolated exception boundaries:

- Every stage visibly transitions pending -> running -> terminal status.
- A failed stage never aborts the session; dependents are skipped.
- Conservative dependencies: analysis needs discovery; candidates need
  discovery and analysis.
- Requested-but-unimplemented stages are skipped, never executed.
- The runner ends at candidates.  It has no execution authority:
  no executor, confirmation, or remediation imports (test-enforced).

First wiring: discovery -> analysis -> candidates, using the existing
implementations (no duplicated subsystem logic):
- discovery: app.discovery.run()
- analysis: app.analyzers.runner.analyze_latest_run()
- candidates: app.reporting.builder.build_health_report(), which is the
  existing live path that delegates to
  app.remediation.policy.evaluate_candidates().  Calling
  evaluate_candidates() directly would require duplicating the
  PolicyContext assembly owned by the reporting builder, so the runner
  reuses the production path instead.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable

from app.health.budgets import DEFAULT_BUDGETS, HealthBudgets
from app.health.models import (
    DataQuality,
    HealthSession,
    HealthStage,
    HealthStageStatus,
    HealthStageType,
    transition_stage,
)
from app.health.profiles import DEFAULT_PROFILE, HealthProfile, get_profile


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _monotonic_ms() -> int:
    return int(time.perf_counter() * 1000)


@dataclass(frozen=True)
class StageInvocation:
    """Inputs handed to a stage handler.  References only, no payloads."""

    session_id: str
    profile: HealthProfile
    budgets: HealthBudgets
    store: Any | None
    discovery_run_id: int | None = None


@dataclass(frozen=True)
class StageOutcome:
    """Result produced by a stage handler."""

    ok: bool
    data_quality: DataQuality = DataQuality.UNKNOWN
    evidence_refs: tuple[str, ...] = ()
    provenance: dict[str, str] = field(default_factory=dict)
    discovery_run_id: int | None = None
    error: str | None = None


StageHandler = Callable[[StageInvocation], StageOutcome]

#: Conservative prerequisites: a stage runs only when each prerequisite
#: completed.  A failed prerequisite skips (never fails) the dependent.
_PREREQUISITES: dict[HealthStageType, tuple[HealthStageType, ...]] = {
    HealthStageType.ANALYSIS: (HealthStageType.DISCOVERY,),
    HealthStageType.HISTORY: (HealthStageType.DISCOVERY,),
    HealthStageType.CANDIDATES: (
        HealthStageType.DISCOVERY,
        HealthStageType.ANALYSIS,
    ),
}


def derive_session_status(
    stages: tuple[HealthStage, ...],
    requested: tuple[HealthStageType, ...],
) -> HealthStageStatus:
    """Derive the session status from stage outcomes.

    - Any required stage failed -> FAILED.
    - All requested completed -> COMPLETED.
    - Requested completed but some other stage skipped -> PARTIAL.
    """
    by_type = {stage.stage_type: stage.status for stage in stages}
    if any(
        by_type.get(stage_type) == HealthStageStatus.FAILED
        for stage_type in requested
    ):
        return HealthStageStatus.FAILED
    if all(
        by_type.get(stage_type) == HealthStageStatus.COMPLETED
        for stage_type in requested
    ):
        return HealthStageStatus.COMPLETED
    return HealthStageStatus.PARTIAL


def derive_data_quality(
    status: HealthStageStatus, stages: tuple[HealthStage, ...]
) -> DataQuality:
    """Derive session data quality from the session status and stages."""
    qualities = {stage.data_quality for stage in stages}
    if status == HealthStageStatus.COMPLETED and qualities <= {
        DataQuality.GOOD
    }:
        return DataQuality.GOOD
    if DataQuality.DEGRADED in qualities or status in (
        HealthStageStatus.PARTIAL,
        HealthStageStatus.FAILED,
    ):
        return DataQuality.DEGRADED
    return DataQuality.UNKNOWN


class HealthSessionRunner:
    """Runs a health session for a profile with stage isolation."""

    def __init__(
        self,
        *,
        profile: str | HealthProfile = DEFAULT_PROFILE,
        budgets: HealthBudgets | None = None,
        store: Any | None = None,
        handlers: dict[HealthStageType, StageHandler] | None = None,
        session_id_factory: Callable[[], str] | None = None,
        utcnow: Callable[[], str] | None = None,
        monotonic_ms: Callable[[], int] | None = None,
    ) -> None:
        self._config = get_profile(profile)
        self._budgets = budgets if budgets is not None else DEFAULT_BUDGETS
        self._store = store
        self._session_id_factory = session_id_factory
        self._utcnow = utcnow if utcnow is not None else _utcnow
        self._monotonic_ms = (
            monotonic_ms if monotonic_ms is not None else _monotonic_ms
        )
        defaults: dict[HealthStageType, StageHandler] = {
            HealthStageType.DISCOVERY: self._handle_discovery,
            HealthStageType.ANALYSIS: self._handle_analysis,
            HealthStageType.CANDIDATES: self._handle_candidates,
        }
        if handlers:
            defaults.update(handlers)
        self._handlers = defaults

    # -- public API ----------------------------------------------------

    def run_session(self) -> HealthSession:
        """Run all profile-requested stages and return the session."""
        now = self._utcnow()
        session_start_ms = self._monotonic_ms()
        session_id = (
            self._session_id_factory()
            if self._session_id_factory is not None
            else f"hs_{now.replace(':', '').replace('-', '')}"
        )
        requested = self._config.stages

        # One shared store for the whole session so analysis and
        # candidates read the discovery run this session collected.
        store = self._store
        if store is None:
            from app.database.sqlite import SnapshotStore

            store = SnapshotStore()

        stages: list[HealthStage] = []
        completed: dict[HealthStageType, HealthStageStatus] = {}
        discovery_run_id: int | None = None
        for stage_type in requested:
            stage, discovery_run_id = self._run_stage(
                session_id, stage_type, completed, discovery_run_id, store
            )
            stages.append(stage)
            completed[stage_type] = stage.status

        completed_at = self._utcnow()
        elapsed_ms = self._monotonic_ms() - session_start_ms
        status = derive_session_status(tuple(stages), requested)
        if elapsed_ms > self._budgets.max_session_runtime_ms:
            status = HealthStageStatus.BUDGET_EXCEEDED

        evidence_ids: list[str] = []
        for stage in stages:
            for ref in stage.evidence_refs:
                if ref not in evidence_ids:
                    evidence_ids.append(ref)

        return HealthSession(
            session_id=session_id,
            profile=self._config.profile.value,
            created_at=now,
            started_at=now,
            completed_at=completed_at,
            status=status,
            stages=tuple(stages),
            budgets=self._budgets.to_dict(),
            data_quality=derive_data_quality(status, tuple(stages)),
            discovery_run_id=discovery_run_id,
            evidence_ids=tuple(evidence_ids),
        )

    # -- stage execution -----------------------------------------------

    def _run_stage(
        self,
        session_id: str,
        stage_type: HealthStageType,
        completed: dict[HealthStageType, HealthStageStatus],
        discovery_run_id: int | None,
        store: Any | None,
    ) -> tuple[HealthStage, int | None]:
        for prerequisite in _PREREQUISITES.get(stage_type, ()):
            if completed.get(prerequisite) != HealthStageStatus.COMPLETED:
                return (
                    self._skipped_stage(
                        session_id,
                        stage_type,
                        f"Skipped because prerequisite stage "
                        f"'{prerequisite.value}' did not complete.",
                    ),
                    discovery_run_id,
                )
        handler = self._handlers.get(stage_type)
        if handler is None:
            return (
                self._skipped_stage(
                    session_id,
                    stage_type,
                    f"Skipped: no runner handler for stage "
                    f"'{stage_type.value}' (not implemented).",
                ),
                discovery_run_id,
            )

        pending = HealthStage(
            stage_id=f"{session_id}:{stage_type.value}",
            stage_type=stage_type,
            status=HealthStageStatus.PENDING,
            started_at=self._utcnow(),
        )
        running = transition_stage(pending, HealthStageStatus.RUNNING)
        start_ms = self._monotonic_ms()
        try:
            outcome = handler(
                StageInvocation(
                    session_id=session_id,
                    profile=self._config.profile,
                    budgets=self._budgets,
                    store=store,
                    discovery_run_id=discovery_run_id,
                )
            )
        except Exception as exc:
            terminal = transition_stage(
                running,
                HealthStageStatus.FAILED,
                completed_at=self._utcnow(),
                duration_ms=max(0, self._monotonic_ms() - start_ms),
                error=f"{stage_type.value} failed: {exc}",
            )
            return terminal, discovery_run_id

        status = (
            HealthStageStatus.COMPLETED
            if outcome.ok
            else HealthStageStatus.FAILED
        )
        if outcome.discovery_run_id is not None:
            discovery_run_id = outcome.discovery_run_id
        terminal = transition_stage(
            running,
            status,
            completed_at=self._utcnow(),
            duration_ms=max(0, self._monotonic_ms() - start_ms),
            error=outcome.error,
        )
        final = replace(
            terminal,
            data_quality=outcome.data_quality,
            evidence_refs=tuple(outcome.evidence_refs),
            evidence_timestamp=terminal.completed_at,
            provenance={
                **outcome.provenance,
                "session_id": session_id,
                "observed_at": self._utcnow(),
            },
        )
        if (
            final.status == HealthStageStatus.COMPLETED
            and final.duration_ms > self._budgets.max_stage_runtime_ms
        ):
            overrun = transition_stage(
                running,
                HealthStageStatus.BUDGET_EXCEEDED,
                completed_at=final.completed_at,
                duration_ms=final.duration_ms,
                error=(
                    (f"{final.error}; " if final.error else "")
                    + f"stage exceeded max_stage_runtime_ms "
                    f"({final.duration_ms} > "
                    f"{self._budgets.max_stage_runtime_ms})"
                ),
            )
            final = replace(
                overrun,
                data_quality=final.data_quality,
                evidence_refs=final.evidence_refs,
                provenance=final.provenance,
            )
        return final, discovery_run_id

    def _skipped_stage(
        self, session_id: str, stage_type: HealthStageType, reason: str
    ) -> HealthStage:
        now = self._utcnow()
        pending = HealthStage(
            stage_id=f"{session_id}:{stage_type.value}",
            stage_type=stage_type,
            status=HealthStageStatus.PENDING,
            started_at=now,
        )
        return transition_stage(
            pending,
            HealthStageStatus.SKIPPED,
            completed_at=now,
            duration_ms=0,
            error=reason,
        )

    # -- default handlers (assessment only, never remediation) ----------

    def _handle_discovery(self, invocation: StageInvocation) -> StageOutcome:
        from app.discovery import run as run_discovery

        _results, summary = run_discovery(store=invocation.store)
        run_id = summary.get("run_id")
        run_id_int = int(run_id) if run_id is not None else None
        return StageOutcome(
            ok=True,
            data_quality=DataQuality.GOOD,
            evidence_refs=(
                (f"discovery_run:{run_id_int}",) if run_id_int else ()
            ),
            provenance={
                "source_type": "discovery",
                "source_id": str(run_id_int),
            },
            discovery_run_id=run_id_int,
        )

    def _handle_analysis(self, invocation: StageInvocation) -> StageOutcome:
        from app.analyzers.runner import analyze_latest_run

        result = analyze_latest_run(invocation.store)
        errors = int(result.get("errors_count", 0) or 0)
        refs = (
            (f"discovery_run:{invocation.discovery_run_id}",)
            if invocation.discovery_run_id is not None
            else ()
        )
        return StageOutcome(
            ok=True,
            data_quality=(
                DataQuality.DEGRADED if errors else DataQuality.GOOD
            ),
            evidence_refs=refs,
            provenance={
                "source_type": "analysis",
                "source_id": str(invocation.discovery_run_id),
            },
        )

    def _handle_candidates(self, invocation: StageInvocation) -> StageOutcome:
        from app.reporting.builder import build_health_report

        report = build_health_report(invocation.store)
        summary = report.action_candidates
        available = getattr(summary, "available", 0)
        refs = (
            (f"discovery_run:{invocation.discovery_run_id}",)
            if invocation.discovery_run_id is not None
            else ()
        )
        return StageOutcome(
            ok=True,
            data_quality=DataQuality.GOOD,
            evidence_refs=refs,
            provenance={
                "source_type": "candidates",
                "source_id": (
                    f"run:{invocation.discovery_run_id}:candidates"
                ),
                "available": str(available),
            },
        )
