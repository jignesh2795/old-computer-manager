"""Action candidate models for diagnostic-to-action intelligence.

This module defines structured candidate actions that connect evidence
to eligible remediation options WITHOUT creating an execution path.

The candidate-generation layer must NOT import or instantiate an executor.
It must NOT have filesystem mutation authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class CandidateStatus(str, Enum):
    """Status of an action candidate.

    Only 'available' actions are both implemented AND eligible.
    """
    AVAILABLE = "available"
    PROPOSED = "proposed"
    BLOCKED = "blocked"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    STALE = "stale"


class EvidenceSourceType(str, Enum):
    """Where the evidence originated."""
    DISCOVERY = "discovery"
    DIAGNOSTIC = "diagnostic"
    FINDING = "finding"
    FILE_ANALYSIS = "file_analysis"
    HISTORICAL = "historical"


@dataclass(frozen=True)
class EvidenceSource:
    """A single piece of evidence supporting a candidate action.

    Evidence must be traceable to actual observations, not AI text.
    """
    source_type: EvidenceSourceType
    source_id: str
    observation: str
    timestamp: str = ""
    value: Any = None
    interpretation: str = ""


@dataclass(frozen=True)
class ActionCandidate:
    """A structured candidate action linking evidence to remediation.

    This is a read-only recommendation. It does NOT grant execution authority.
    The existing remediation safety chain is the only route to actual changes.
    """
    candidate_id: str
    action_id: str
    status: CandidateStatus
    title: str
    reason: str
    evidence: list[EvidenceSource] = field(default_factory=list)
    source_finding_ids: list[int] = field(default_factory=list)
    source_diagnostic_ids: list[str] = field(default_factory=list)
    discovery_run_id: int | None = None
    confidence_basis: str = ""
    eligibility_status: str = ""
    implementation_status: str = ""
    risk_level: str = ""
    blast_radius: str = ""
    reversible: bool = False
    requires_admin: bool = False
    preview_available: bool = False
    rollback_available: bool = False
    limitations: list[str] = field(default_factory=list)
    stale_after: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def executable(self) -> bool:
        """Candidates are NEVER directly executable.

        Execution requires the existing remediation safety chain.
        """
        return False


@dataclass(frozen=True)
class CandidatesSummary:
    """Bounded summary of action candidates for reporting."""
    available_count: int = 0
    proposed_count: int = 0
    blocked_count: int = 0
    insufficient_evidence_count: int = 0
    stale_count: int = 0
    total_count: int = 0
    candidates: list[ActionCandidate] = field(default_factory=list)
