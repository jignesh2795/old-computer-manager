"""Health orchestration domain (Phase 12).

Owns the HealthSession contract.  Must not import executor,
confirmation, or subprocess.
"""

from app.health.budgets import DEFAULT_BUDGETS, HealthBudgets
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
from app.health.profiles import (
    DEFAULT_PROFILE,
    PROFILES,
    HealthProfile,
    ProfileConfig,
    get_profile,
    is_stage_enabled,
)

__all__ = [
    "TERMINAL_STATUSES",
    "DEFAULT_BUDGETS",
    "DEFAULT_PROFILE",
    "PROFILES",
    "DataQuality",
    "HealthBudgets",
    "HealthProfile",
    "HealthSession",
    "HealthStage",
    "HealthStageStatus",
    "HealthStageType",
    "ProfileConfig",
    "get_profile",
    "is_legal_transition",
    "is_stage_enabled",
    "transition_stage",
]
