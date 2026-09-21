"""Health run profiles (Phase 12.2).

Profiles declare *what stages are requested*.  They contain no execution
logic; the runner consumes them.  Diagnostics and AI are explicitly
requested work, never hidden side effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from app.health.models import HealthStageType


class HealthProfile(str, Enum):
    """Available health run profiles."""

    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"
    DIAGNOSTIC = "diagnostic"
    ADVISORY = "advisory"


DEFAULT_PROFILE = HealthProfile.QUICK


@dataclass(frozen=True)
class ProfileConfig:
    """Immutable stage selection for a profile, in run order."""

    profile: HealthProfile
    stages: tuple[HealthStageType, ...]
    description: str = ""

    def is_enabled(self, stage_type: HealthStageType) -> bool:
        """Return True when the stage is requested by this profile."""
        return stage_type in self.stages

    def to_dict(self) -> dict:
        """Deterministic serialization (fixed key order)."""
        return {
            "profile": self.profile.value,
            "stages": [stage.value for stage in self.stages],
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ProfileConfig:
        """Deserialize; raises ValueError on unknown profile or stage."""
        return cls(
            profile=HealthProfile(data["profile"]),
            stages=tuple(
                HealthStageType(stage) for stage in data.get("stages", [])
            ),
            description=data.get("description", ""),
        )


PROFILES: dict[HealthProfile, ProfileConfig] = {
    HealthProfile.QUICK: ProfileConfig(
        profile=HealthProfile.QUICK,
        stages=(
            HealthStageType.DISCOVERY,
            HealthStageType.ANALYSIS,
            HealthStageType.CANDIDATES,
        ),
        description="Lightweight assessment for older hardware.",
    ),
    HealthProfile.STANDARD: ProfileConfig(
        profile=HealthProfile.STANDARD,
        stages=(
            HealthStageType.DISCOVERY,
            HealthStageType.ANALYSIS,
            HealthStageType.HISTORY,
            HealthStageType.CANDIDATES,
        ),
        description="Standard assessment with history baseline.",
    ),
    HealthProfile.FULL: ProfileConfig(
        profile=HealthProfile.FULL,
        stages=(
            HealthStageType.DISCOVERY,
            HealthStageType.ANALYSIS,
            HealthStageType.HISTORY,
            HealthStageType.CANDIDATES,
        ),
        description=(
            "Full assessment. Diagnostics and AI stay disabled until "
            "their optional orchestration lands; they are never enabled "
            "silently."
        ),
    ),
    HealthProfile.DIAGNOSTIC: ProfileConfig(
        profile=HealthProfile.DIAGNOSTIC,
        stages=(
            HealthStageType.DISCOVERY,
            HealthStageType.ANALYSIS,
            HealthStageType.DIAGNOSTICS,
            HealthStageType.CANDIDATES,
        ),
        description="Assessment with explicitly requested diagnostics.",
    ),
    HealthProfile.ADVISORY: ProfileConfig(
        profile=HealthProfile.ADVISORY,
        stages=(
            HealthStageType.DISCOVERY,
            HealthStageType.ANALYSIS,
            HealthStageType.HISTORY,
            HealthStageType.AI,
            HealthStageType.CANDIDATES,
        ),
        description="Assessment with explicitly requested AI advisory.",
    ),
}


def get_profile(name: str | HealthProfile) -> ProfileConfig:
    """Return the config for a profile name; rejects unknown profiles."""
    profile = (
        name if isinstance(name, HealthProfile) else HealthProfile(name)
    )
    return PROFILES[profile]


def is_stage_enabled(
    profile: str | HealthProfile, stage_type: HealthStageType
) -> bool:
    """Return True when the profile requests the stage."""
    return get_profile(profile).is_enabled(stage_type)
