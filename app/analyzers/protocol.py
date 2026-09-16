"""Analyzer protocol defining the contract for all analyzers."""

from __future__ import annotations

from typing import Any, Protocol

from app.analyzers.finding import Finding


class Analyzer(Protocol):
    """Every analyzer must satisfy this interface.

    An analyzer receives a dict of relevant snapshot payloads (keyed by
    discovery category name) and returns a list of Finding objects.
    It must not raise exceptions; the runner catches them.
    """

    name: str

    def analyze(self, snapshots: dict[str, Any]) -> list[Finding]: ...
