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
    HealthStageType.DIAGNOSTICS: (
        HealthStageType.DISCOVERY,
        HealthStageType.ANALYSIS,
    ),
    HealthStageType.AI: (
        HealthStageType.DISCOVERY,
        HealthStageType.ANALYSIS,
    ),
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

    - Discovery failed -> FAILED (no evidence downstream).
    - Candidates failed/skipped -> FAILED (primary output missing).
    - All requested completed -> COMPLETED.
    - Otherwise -> PARTIAL (auxiliary stages failed or skipped while
      the primary output was still produced).
    """
    by_type = {stage.stage_type: stage.status for stage in stages}
    if (
        HealthStageType.DISCOVERY in requested
        and by_type.get(HealthStageType.DISCOVERY)
        == HealthStageStatus.FAILED
    ):
        return HealthStageStatus.FAILED
    if HealthStageType.CANDIDATES in requested:
        candidates_status = by_type.get(HealthStageType.CANDIDATES)
        if candidates_status in (
            HealthStageStatus.FAILED,
            HealthStageStatus.SKIPPED,
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
        session_store: Any | None = None,
        handlers: dict[HealthStageType, StageHandler] | None = None,
        session_id_factory: Callable[[], str] | None = None,
        utcnow: Callable[[], str] | None = None,
        monotonic_ms: Callable[[], int] | None = None,
    ) -> None:
        self._config = get_profile(profile)
        self._budgets = budgets if budgets is not None else DEFAULT_BUDGETS
        self._store = store
        self._session_store = session_store
        self.last_persistence_errors: list[str] = []
        self._session_id_factory = session_id_factory
        self._utcnow = utcnow if utcnow is not None else _utcnow
        self._monotonic_ms = (
            monotonic_ms if monotonic_ms is not None else _monotonic_ms
        )
        defaults: dict[HealthStageType, StageHandler] = {
            HealthStageType.DISCOVERY: self._handle_discovery,
            HealthStageType.ANALYSIS: self._handle_analysis,
            HealthStageType.HISTORY: self._handle_history,
            HealthStageType.DIAGNOSTICS: self._handle_diagnostics,
            HealthStageType.AI: self._handle_ai,
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

        self.last_persistence_errors = []
        persist = self._session_store is not None
        self._persist_session(
            HealthSession(
                session_id=session_id,
                profile=self._config.profile.value,
                created_at=now,
                started_at=now,
                status=HealthStageStatus.RUNNING,
                budgets=self._budgets.to_dict(),
            )
        )
        persist = persist and not self.last_persistence_errors

        stages: list[HealthStage] = []
        completed: dict[HealthStageType, HealthStageStatus] = {}
        discovery_run_id: int | None = None
        for stage_type in requested:
            stage, discovery_run_id = self._run_stage(
                session_id, stage_type, completed, discovery_run_id, store
            )
            stages.append(stage)
            completed[stage_type] = stage.status
            if persist:
                self._persist_stage(session_id, stage)

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

        session = HealthSession(
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
        if persist:
            self._persist_session_final(session)
        return session

    def _persist_session(self, session: HealthSession) -> None:
        """Persist the opened session; storage failure is recorded."""
        if self._session_store is None:
            return
        try:
            self._session_store.create_session(session)
        except Exception as exc:
            self.last_persistence_errors.append(
                f"create_session failed: {exc}"
            )

    def _persist_stage(self, session_id: str, stage: HealthStage) -> None:
        """Persist one stage; storage failure is recorded."""
        if self._session_store is None:
            return
        try:
            self._session_store.save_stage(session_id, stage)
        except Exception as exc:
            self.last_persistence_errors.append(
                f"save_stage {stage.stage_type.value} failed: {exc}"
            )

    def _persist_session_final(self, session: HealthSession) -> None:
        """Persist the finalized session; storage failure is recorded."""
        if self._session_store is None:
            return
        try:
            self._session_store.finalize_session(session)
        except Exception as exc:
            self.last_persistence_errors.append(
                f"finalize_session failed: {exc}"
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
        error = outcome.error
        if (
            status == HealthStageStatus.COMPLETED
            and len(outcome.evidence_refs)
            > self._budgets.max_evidence_items
        ):
            status = HealthStageStatus.BUDGET_EXCEEDED
            error = (
                (f"{error}; " if error else "")
                + f"stage exceeded max_evidence_items "
                f"({len(outcome.evidence_refs)} > "
                f"{self._budgets.max_evidence_items})"
            )
        if outcome.discovery_run_id is not None:
            discovery_run_id = outcome.discovery_run_id
        terminal = transition_stage(
            running,
            status,
            completed_at=self._utcnow(),
            duration_ms=max(0, self._monotonic_ms() - start_ms),
            error=error,
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
            final = self._to_budget_exceeded(
                running,
                final,
                f"stage exceeded max_stage_runtime_ms "
                f"({final.duration_ms} > "
                f"{self._budgets.max_stage_runtime_ms})",
            )
        if (
            final.status == HealthStageStatus.COMPLETED
            and final.error is not None
            and "max_ai_context_items" in final.error
        ):
            final = self._to_budget_exceeded(running, final, None)
        return final, discovery_run_id

    def _to_budget_exceeded(
        self,
        running: HealthStage,
        final: HealthStage,
        message: str | None,
    ) -> HealthStage:
        """Move a completed stage to budget_exceeded via the contract."""
        base = final.error or ""
        if message and message not in base:
            base = f"{base}; {message}" if base else message
        overrun = transition_stage(
            running,
            HealthStageStatus.BUDGET_EXCEEDED,
            completed_at=final.completed_at,
            duration_ms=final.duration_ms,
            error=base or None,
        )
        return replace(
            overrun,
            data_quality=final.data_quality,
            evidence_refs=final.evidence_refs,
            evidence_timestamp=final.evidence_timestamp,
            provenance=final.provenance,
        )

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

    def _handle_history(self, invocation: StageInvocation) -> StageOutcome:
        from app.history.runner import run_history

        summary = run_history(
            invocation.store,
            limit=invocation.budgets.max_history_runs,
        )
        runs_considered = int(
            getattr(summary, "runs_considered", 0) or 0
        )
        refs = (
            (f"discovery_run:{invocation.discovery_run_id}",)
            if invocation.discovery_run_id is not None
            else ()
        )
        return StageOutcome(
            ok=True,
            data_quality=(
                DataQuality.GOOD
                if runs_considered > 0
                else DataQuality.UNKNOWN
            ),
            evidence_refs=refs,
            provenance={
                "source_type": "history",
                "source_id": str(invocation.discovery_run_id),
                "runs_considered": str(runs_considered),
            },
        )

    def _handle_diagnostics(
        self, invocation: StageInvocation
    ) -> StageOutcome:
        from app.diagnostics.runner import run_diagnostics, save_diagnostic_run

        run = run_diagnostics(
            discovery_run_id=invocation.discovery_run_id
        )
        diagnostic_run_id = save_diagnostic_run(run, invocation.store)
        refs: tuple[str, ...] = ()
        if diagnostic_run_id is not None:
            refs = (f"diagnostic_run:{diagnostic_run_id}",)
        elif invocation.discovery_run_id is not None:
            refs = (f"discovery_run:{invocation.discovery_run_id}",)
        errors = len(getattr(run, "errors", []) or [])
        return StageOutcome(
            ok=True,
            data_quality=(
                DataQuality.GOOD
                if getattr(run, "status", "") == "completed"
                else DataQuality.DEGRADED
            ),
            evidence_refs=refs,
            provenance={
                "source_type": "diagnostics",
                "source_id": str(diagnostic_run_id),
                "errors": str(errors),
            },
        )

    def _handle_ai(self, invocation: StageInvocation) -> StageOutcome:
        from app.ai.runner import run_advisory

        advisory = run_advisory(invocation.store)
        item_count = (
            len(getattr(advisory, "observations", []) or [])
            + len(getattr(advisory, "recommendations", []) or [])
            + len(getattr(advisory, "uncertainties", []) or [])
        )
        refs = (
            (f"discovery_run:{invocation.discovery_run_id}",)
            if invocation.discovery_run_id is not None
            else ()
        )
        if item_count > invocation.budgets.max_ai_context_items:
            return StageOutcome(
                ok=True,
                data_quality=DataQuality.DEGRADED,
                evidence_refs=refs,
                provenance={
                    "source_type": "ai",
                    "source_id": str(invocation.discovery_run_id),
                    "context_items": str(item_count),
                },
                error=(
                    f"advisory exceeded max_ai_context_items "
                    f"({item_count} > "
                    f"{invocation.budgets.max_ai_context_items})"
                ),
            )
        return StageOutcome(
            ok=True,
            data_quality=DataQuality.GOOD,
            evidence_refs=refs,
            provenance={
                "source_type": "ai",
                "source_id": str(invocation.discovery_run_id),
                "context_items": str(item_count),
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
