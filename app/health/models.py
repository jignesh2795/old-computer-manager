"""Health session domain model (Phase 12.1).

Orchestration contract for computer-health assessments.  This module owns
orchestration status and never reuses collector/diagnostic statuses.

Safety boundaries:
- A session references evidence (IDs, timestamps) and never duplicates
  payloads.
- This module must not import executor, confirmation, or subprocess
  (enforced by tests).
- The orchestrator never executes remediation; it ends at candidates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class HealthStageType(str, Enum):
    """Stages a health session can orchestrate."""

    DISCOVERY = "discovery"
    ANALYSIS = "analysis"
    HISTORY = "history"
    DIAGNOSTICS = "diagnostics"
    AI = "ai"
    CANDIDATES = "candidates"


class HealthStageStatus(str, Enum):
    """Orchestration-level status for sessions and stages.

    Distinct from collector/diagnostic statuses, which describe data
    collection outcomes rather than orchestration state.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    BUDGET_EXCEEDED = "budget_exceeded"
    STALE = "stale"


class DataQuality(str, Enum):
    """Quality of the evidence behind a session or stage."""

    GOOD = "good"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


TERMINAL_STATUSES: frozenset[HealthStageStatus] = frozenset(
    {
        HealthStageStatus.COMPLETED,
        HealthStageStatus.PARTIAL,
        HealthStageStatus.FAILED,
        HealthStageStatus.SKIPPED,
        HealthStageStatus.BUDGET_EXCEEDED,
        HealthStageStatus.STALE,
    }
)

_LEGAL_TRANSITIONS: dict[HealthStageStatus, frozenset[HealthStageStatus]] = {
    HealthStageStatus.PENDING: frozenset(
        {HealthStageStatus.RUNNING, HealthStageStatus.SKIPPED}
    ),
    HealthStageStatus.RUNNING: frozenset(
        {
            HealthStageStatus.COMPLETED,
            HealthStageStatus.PARTIAL,
            HealthStageStatus.FAILED,
            HealthStageStatus.SKIPPED,
            HealthStageStatus.BUDGET_EXCEEDED,
            HealthStageStatus.STALE,
        }
    ),
    HealthStageStatus.COMPLETED: frozenset(),
    HealthStageStatus.PARTIAL: frozenset(),
    HealthStageStatus.FAILED: frozenset(),
    HealthStageStatus.SKIPPED: frozenset(),
    HealthStageStatus.BUDGET_EXCEEDED: frozenset(),
    HealthStageStatus.STALE: frozenset(),
}


def is_legal_transition(
    from_status: HealthStageStatus, to_status: HealthStageStatus
) -> bool:
    """Return True when moving from one status to another is allowed."""
    return to_status in _LEGAL_TRANSITIONS[from_status]


@dataclass(frozen=True)
class HealthStage:
    """A single orchestrated stage within a health session.

    Evidence is referenced (IDs, timestamps), never embedded.
    """

    stage_id: str
    stage_type: HealthStageType
    status: HealthStageStatus = HealthStageStatus.PENDING
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: int = 0
    error: str | None = None
    evidence_timestamp: str | None = None
    data_quality: DataQuality = DataQuality.UNKNOWN
    provenance: dict[str, str] = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.stage_type, HealthStageType):
            raise ValueError(f"Invalid stage_type: {self.stage_type!r}")
        if not isinstance(self.status, HealthStageStatus):
            raise ValueError(f"Invalid status: {self.status!r}")
        if not isinstance(self.data_quality, DataQuality):
            raise ValueError(f"Invalid data_quality: {self.data_quality!r}")
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be >= 0")

    def to_dict(self) -> dict:
        """Deterministic serialization (fixed key order)."""
        return {
            "stage_id": self.stage_id,
            "stage_type": self.stage_type.value,
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "evidence_timestamp": self.evidence_timestamp,
            "data_quality": self.data_quality.value,
            "provenance": dict(self.provenance),
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, data: dict) -> HealthStage:
        """Deserialize; raises ValueError on unknown enum values."""
        return cls(
            stage_id=data["stage_id"],
            stage_type=HealthStageType(data["stage_type"]),
            status=HealthStageStatus(data["status"]),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            duration_ms=data.get("duration_ms", 0),
            error=data.get("error"),
            evidence_timestamp=data.get("evidence_timestamp"),
            data_quality=DataQuality(data.get("data_quality", "unknown")),
            provenance=dict(data.get("provenance", {})),
            evidence_refs=tuple(data.get("evidence_refs", [])),
        )


@dataclass(frozen=True)
class HealthSession:
    """An orchestrated computer-health assessment.

    References existing evidence (discovery runs, observation IDs) rather
    than duplicating payloads.
    """

    session_id: str
    profile: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    status: HealthStageStatus = HealthStageStatus.PENDING
    stages: tuple[HealthStage, ...] = ()
    budgets: dict[str, int] = field(default_factory=dict)
    data_quality: DataQuality = DataQuality.UNKNOWN
    discovery_run_id: int | None = None
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, HealthStageStatus):
            raise ValueError(f"Invalid status: {self.status!r}")
        if not isinstance(self.data_quality, DataQuality):
            raise ValueError(f"Invalid data_quality: {self.data_quality!r}")
        for budget_name, budget_value in self.budgets.items():
            if budget_value < 0:
                raise ValueError(
                    f"Budget '{budget_name}' must be >= 0"
                )

    def to_dict(self) -> dict:
        """Deterministic serialization (fixed key order)."""
        return {
            "session_id": self.session_id,
            "profile": self.profile,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status.value,
            "stages": [stage.to_dict() for stage in self.stages],
            "budgets": dict(self.budgets),
            "data_quality": self.data_quality.value,
            "discovery_run_id": self.discovery_run_id,
            "evidence_ids": list(self.evidence_ids),
        }

    @classmethod
    def from_dict(cls, data: dict) -> HealthSession:
        """Deserialize; raises ValueError on unknown enum values."""
        return cls(
            session_id=data["session_id"],
            profile=data["profile"],
            created_at=data["created_at"],
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            status=HealthStageStatus(data.get("status", "pending")),
            stages=tuple(
                HealthStage.from_dict(item)
                for item in data.get("stages", [])
            ),
            budgets=dict(data.get("budgets", {})),
            data_quality=DataQuality(data.get("data_quality", "unknown")),
            discovery_run_id=data.get("discovery_run_id"),
            evidence_ids=tuple(data.get("evidence_ids", [])),
        )


def transition_stage(
    stage: HealthStage,
    to_status: HealthStageStatus,
    *,
    completed_at: str | None = None,
    duration_ms: int | None = None,
    error: str | None = None,
) -> HealthStage:
    """Return a new stage moved to ``to_status``.

    Raises ValueError when the transition is not legal.
    """
    if not isinstance(to_status, HealthStageStatus):
        raise ValueError(f"Invalid status: {to_status!r}")
    if not is_legal_transition(stage.status, to_status):
        raise ValueError(
            f"Illegal stage transition: "
            f"{stage.status.value} -> {to_status.value}"
        )
    return HealthStage(
        stage_id=stage.stage_id,
        stage_type=stage.stage_type,
        status=to_status,
        started_at=stage.started_at,
        completed_at=(
            completed_at if completed_at is not None else stage.completed_at
        ),
        duration_ms=(
            duration_ms if duration_ms is not None else stage.duration_ms
        ),
        error=error if error is not None else stage.error,
        evidence_timestamp=stage.evidence_timestamp,
        data_quality=stage.data_quality,
        provenance=dict(stage.provenance),
        evidence_refs=tuple(stage.evidence_refs),
    )
