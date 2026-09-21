"""Health orchestration domain (Phase 12).

Owns the HealthSession contract.  Must not import executor,
confirmation, or subprocess.
"""

from app.health.models import (
    TERMINAL_STATUSES,
    DataQuality,
    HealthSession,
    HealthStage,
    HealthStageStatus,
    HealthStageType,
    is_legal_transition,
    transition_stage,
)

__all__ = [
    "TERMINAL_STATUSES",
    "DataQuality",
    "HealthSession",
    "HealthStage",
    "HealthStageStatus",
    "HealthStageType",
    "is_legal_transition",
    "transition_stage",
]
