"""Phase 12.2 tests: health run profiles."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.health.models import HealthStageType
from app.health.profiles import (
    DEFAULT_PROFILE,
    PROFILES,
    HealthProfile,
    ProfileConfig,
    get_profile,
    is_stage_enabled,
)


class TestAllProfilesExist:
    def test_five_profiles(self):
        assert {p.value for p in HealthProfile} == {
            "quick",
            "standard",
            "full",
            "diagnostic",
            "advisory",
        }
        assert set(PROFILES) == set(HealthProfile)

    def test_default_profile_is_quick(self):
        assert DEFAULT_PROFILE == HealthProfile.QUICK


class TestStageMatrix:
    def test_quick(self):
        config = get_profile("quick")
        assert config.is_enabled(HealthStageType.DISCOVERY)
        assert config.is_enabled(HealthStageType.ANALYSIS)
        assert config.is_enabled(HealthStageType.CANDIDATES)
        assert not config.is_enabled(HealthStageType.HISTORY)
        assert not config.is_enabled(HealthStageType.DIAGNOSTICS)
        assert not config.is_enabled(HealthStageType.AI)

    def test_standard(self):
        config = get_profile("standard")
        assert config.is_enabled(HealthStageType.HISTORY)
        assert not config.is_enabled(HealthStageType.DIAGNOSTICS)
        assert not config.is_enabled(HealthStageType.AI)

    def test_full_has_no_silent_diagnostics_or_ai(self):
        config = get_profile("full")
        assert not config.is_enabled(HealthStageType.DIAGNOSTICS)
        assert not config.is_enabled(HealthStageType.AI)

    def test_diagnostic(self):
        config = get_profile("diagnostic")
        assert config.is_enabled(HealthStageType.DIAGNOSTICS)
        assert not config.is_enabled(HealthStageType.HISTORY)
        assert not config.is_enabled(HealthStageType.AI)

    def test_advisory(self):
        config = get_profile("advisory")
        assert config.is_enabled(HealthStageType.AI)
        assert config.is_enabled(HealthStageType.HISTORY)
        assert not config.is_enabled(HealthStageType.DIAGNOSTICS)

    def test_helper_accepts_enum_and_name(self):
        assert is_stage_enabled(
            HealthProfile.QUICK, HealthStageType.DISCOVERY
        )
        assert is_stage_enabled("quick", HealthStageType.DISCOVERY)
        assert not is_stage_enabled("quick", HealthStageType.AI)


class TestUnknownProfile:
    def test_unknown_profile_rejected(self):
        with pytest.raises(ValueError):
            get_profile("turbo")

    def test_unknown_stage_in_config_rejected(self):
        with pytest.raises(ValueError):
            ProfileConfig.from_dict({"profile": "quick", "stages": ["nope"]})


class TestSerialization:
    def test_round_trip(self):
        for config in PROFILES.values():
            assert ProfileConfig.from_dict(config.to_dict()) == config

    def test_deterministic(self):
        config = get_profile("standard")
        first = json.dumps(config.to_dict(), sort_keys=True)
        second = json.dumps(
            ProfileConfig.from_dict(config.to_dict()).to_dict(),
            sort_keys=True,
        )
        assert first == second


class TestImmutability:
    def test_profiles_cannot_mutate(self):
        config = get_profile("quick")
        with pytest.raises(Exception):
            config.stages = ()  # type: ignore[misc]


class TestImportBoundary:
    def test_no_forbidden_imports(self):
        import ast

        for filename in ("profiles.py", "budgets.py", "models.py"):
            path = (
                Path(__file__).resolve().parent.parent
                / "app"
                / "health"
                / filename
            )
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    imported = [node.module or ""]
                else:
                    continue
                for name in imported:
                    assert "executor" not in name
                    assert "confirmation" not in name
                    assert "subprocess" not in name
