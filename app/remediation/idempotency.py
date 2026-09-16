"""Idempotency definitions for remediation actions."""

from __future__ import annotations

from enum import Enum


class Idempotency(str, Enum):
    """Whether repeating an action produces the same result.

    IDEMPOTENT: Repeating the action when the desired state is already
        reached has no additional effect.
    NON_IDEMPOTENT: Repeating the action may produce unintended side
        effects (e.g., duplicate entries, toggling a setting back).
    """

    IDEMPOTENT = "idempotent"
    NON_IDEMPOTENT = "non_idempotent"
