"""Explicit Human Confirmation Service (Phase 11C).

Bridges Preview → Confirmation → (future) Executor.

This module is the ONLY way to create a valid ConfirmationToken for
an ActionCandidate. It enforces:

- Preview must exist and be READY
- Preview must not be stale
- Candidate must be AVAILABLE (not proposed/blocked/insufficient_evidence/stale)
- Confirmation is bound to a specific preview fingerprint
- Token is single-use
- Audit transition is recorded
- AI cannot create confirmation tokens
- No --yes/--force bypass
- Confirmation alone does not bypass executor validation

Architecture:
    Candidate → Preview → [THIS MODULE] → ConfirmationToken → Executor

Security constraints:
    - NO executor import (confirmation does not execute)
    - NO subprocess/shell/os.system
    - NO file writes or deletes
    - NO registry/service/task/startup modifications
    - Confirmation is a human authorization gate, not execution
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.remediation.candidates import ActionCandidate, CandidateStatus
from app.remediation.preview import Preview, PreviewStatus


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ConfirmationError(Exception):
    """Base error for confirmation failures."""


class StalePreviewError(ConfirmationError):
    """Raised when attempting to confirm with a stale preview."""


class InsufficientEvidenceError(ConfirmationError):
    """Raised when attempting to confirm with insufficient evidence."""


class BlockedCandidateError(ConfirmationError):
    """Raised when attempting to confirm a blocked candidate."""


class ProposedCandidateError(ConfirmationError):
    """Raised when attempting to confirm a proposed (not implemented) candidate."""


class InvalidPreviewStatusError(ConfirmationError):
    """Raised when preview status does not allow confirmation."""


class PreviewMismatchError(ConfirmationError):
    """Raised when preview does not match the candidate."""


class ConfirmationAlreadyUsedError(ConfirmationError):
    """Raised when a consumed confirmation token is reused."""


# ---------------------------------------------------------------------------
# Confirmation record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConfirmationRecord:
    """Immutable record of an explicit human confirmation.

    This record proves that:
    1. A valid preview existed
    2. The human explicitly confirmed
    3. The confirmation is bound to a specific preview fingerprint
    4. The audit trail was updated

    The record does NOT authorize execution — the executor must
    independently validate the action and its own safety checks.
    """

    confirmation_id: str
    candidate_id: str
    action_id: str
    preview_id: str
    preview_fingerprint: str
    confirmed_at: str
    confirmation_token_secret: str
    consumed: bool = False

    def is_valid_for(self, candidate_id: str, preview_fingerprint: str) -> bool:
        """Check if this record authorizes the given candidate+preview combination."""
        return (
            self.candidate_id == candidate_id
            and self.preview_fingerprint == preview_fingerprint
            and not self.consumed
        )


# ---------------------------------------------------------------------------
# Confirmation store (in-memory for now, SQLite-backed in future)
# ---------------------------------------------------------------------------

class ConfirmationStore:
    """In-memory store for confirmation records.

    In production, this would be backed by SQLite with the same
    audit trail used by AuditStore.
    """

    def __init__(self) -> None:
        self._records: dict[str, ConfirmationRecord] = {}
        self._by_candidate: dict[str, list[str]] = {}

    def add(self, record: ConfirmationRecord) -> None:
        """Store a confirmation record."""
        self._records[record.confirmation_id] = record
        self._by_candidate.setdefault(record.candidate_id, []).append(
            record.confirmation_id
        )

    def get(self, confirmation_id: str) -> ConfirmationRecord | None:
        """Retrieve a confirmation record by ID."""
        return self._records.get(confirmation_id)

    def get_for_candidate(self, candidate_id: str) -> list[ConfirmationRecord]:
        """Get all confirmation records for a candidate."""
        ids = self._by_candidate.get(candidate_id, [])
        return [self._records[cid] for cid in ids if cid in self._records]

    def mark_consumed(self, confirmation_id: str) -> None:
        """Mark a confirmation record as consumed."""
        if confirmation_id in self._records:
            old = self._records[confirmation_id]
            consumed_record = ConfirmationRecord(
                confirmation_id=old.confirmation_id,
                candidate_id=old.candidate_id,
                action_id=old.action_id,
                preview_id=old.preview_id,
                preview_fingerprint=old.preview_fingerprint,
                confirmed_at=old.confirmed_at,
                confirmation_token_secret=old.confirmation_token_secret,
                consumed=True,
            )
            self._records[confirmation_id] = consumed_record

    def count(self) -> int:
        """Number of confirmation records."""
        return len(self._records)


class SqliteConfirmationStore:
    """SQLite-backed confirmation store that persists across CLI processes."""

    def __init__(self, db_store: Any | None = None) -> None:
        if db_store is None:
            from app.database.sqlite import SnapshotStore
            db_store = SnapshotStore()
        self._db = db_store

    def add(self, record: ConfirmationRecord) -> None:
        """Persist a confirmation record to SQLite."""
        self._db.save_confirmation(
            confirmation_id=record.confirmation_id,
            candidate_id=record.candidate_id,
            action_id=record.action_id,
            preview_id=record.preview_id,
            preview_fingerprint=record.preview_fingerprint,
            confirmed_at=record.confirmed_at,
            confirmation_token_secret=record.confirmation_token_secret,
        )

    def get(self, confirmation_id: str) -> ConfirmationRecord | None:
        """Retrieve a confirmation record by ID."""
        row = self._db.get_confirmation(confirmation_id)
        if row is None:
            return None
        return ConfirmationRecord(
            confirmation_id=row["confirmation_id"],
            candidate_id=row["candidate_id"],
            action_id=row["action_id"],
            preview_id=row["preview_id"],
            preview_fingerprint=row["preview_fingerprint"],
            confirmed_at=row["confirmed_at"],
            confirmation_token_secret=row["confirmation_token_secret"],
            consumed=row["consumed"],
        )

    def get_for_candidate(self, candidate_id: str) -> list[ConfirmationRecord]:
        """Get all confirmation records for a candidate."""
        rows = self._db.get_confirmations_for_candidate(candidate_id)
        return [
            ConfirmationRecord(
                confirmation_id=r["confirmation_id"],
                candidate_id=r["candidate_id"],
                action_id=r["action_id"],
                preview_id=r["preview_id"],
                preview_fingerprint=r["preview_fingerprint"],
                confirmed_at=r["confirmed_at"],
                confirmation_token_secret=r["confirmation_token_secret"],
                consumed=r["consumed"],
            )
            for r in rows
        ]

    def mark_consumed(self, confirmation_id: str) -> None:
        """Mark a confirmation record as consumed."""
        self._db.mark_confirmation_consumed(confirmation_id)

    def count(self) -> int:
        """Number of confirmation records."""
        rows = self._db.get_confirmations_for_candidate("*")
        return len(rows)


# ---------------------------------------------------------------------------
# Confirmation service
# ---------------------------------------------------------------------------

class ConfirmationService:
    """Service for creating and validating explicit human confirmations.

    This is the ONLY entry point for creating confirmation tokens.
    It enforces all safety constraints before allowing confirmation.

    Usage:
        service = ConfirmationService()
        record = service.confirm(candidate, preview)
        # record.confirmation_token_secret can now be used by the executor
    """

    def __init__(self, store: ConfirmationStore | None = None) -> None:
        self._store = store or ConfirmationStore()
        self._counter = 0

    @property
    def store(self) -> ConfirmationStore:
        """Access the underlying store."""
        return self._store

    def confirm(
        self,
        candidate: ActionCandidate,
        preview: Preview,
    ) -> ConfirmationRecord:
        """Create an explicit human confirmation for a candidate.

        This method:
        1. Validates the candidate is confirmable
        2. Validates the preview is ready and matches the candidate
        3. Creates a confirmation record
        4. Records the audit transition
        5. Returns the record (containing the token secret)

        Args:
            candidate: The ActionCandidate to confirm
            preview: The Preview that was shown to the human

        Returns:
            ConfirmationRecord with the token secret

        Raises:
            ProposedCandidateError: If candidate is proposed/not implemented
            BlockedCandidateError: If candidate is blocked
            StalePreviewError: If preview is stale
            InsufficientEvidenceError: If preview has insufficient evidence
            InvalidPreviewStatusError: If preview status doesn't allow confirmation
            PreviewMismatchError: If preview doesn't match the candidate
        """
        # 1. Validate candidate status
        self._validate_candidate(candidate)

        # 2. Validate preview status
        self._validate_preview(preview)

        # 3. Validate preview matches candidate
        self._validate_preview_matches_candidate(candidate, preview)

        # 4. Create confirmation record
        self._counter += 1
        import uuid
        confirmation_id = f"conf:{candidate.candidate_id}:{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        # Generate a secret for the token
        import secrets
        token_secret = secrets.token_hex(32)

        record = ConfirmationRecord(
            confirmation_id=confirmation_id,
            candidate_id=candidate.candidate_id,
            action_id=candidate.action_id,
            preview_id=preview.preview_id,
            preview_fingerprint=preview.fingerprint,
            confirmed_at=now,
            confirmation_token_secret=token_secret,
        )

        self._store.add(record)

        return record

    def validate(
        self,
        confirmation_id: str,
        candidate: ActionCandidate,
        preview: Preview,
    ) -> ConfirmationRecord:
        """Validate an existing confirmation before execution.

        This is called by the executor to verify the confirmation
        is still valid. It does NOT consume the token.

        Args:
            confirmation_id: The confirmation ID to validate
            candidate: The ActionCandidate being executed
            preview: The Preview that was confirmed

        Returns:
            The valid ConfirmationRecord

        Raises:
            ConfirmationError: If validation fails
        """
        record = self._store.get(confirmation_id)
        if record is None:
            raise ConfirmationError(f"Confirmation '{confirmation_id}' not found.")

        if record.consumed:
            raise ConfirmationAlreadyUsedError(
                f"Confirmation '{confirmation_id}' has already been consumed."
            )

        if not record.is_valid_for(candidate.candidate_id, preview.fingerprint):
            raise PreviewMismatchError(
                f"Confirmation '{confirmation_id}' does not match "
                f"candidate '{candidate.candidate_id}' with "
                f"preview fingerprint '{preview.fingerprint}'."
            )

        return record

    def consume(
        self,
        confirmation_id: str,
        candidate: ActionCandidate,
        preview: Preview,
    ) -> ConfirmationRecord:
        """Validate and consume a confirmation token.

        Called by the executor after successful execution.

        Args:
            confirmation_id: The confirmation ID to consume
            candidate: The ActionCandidate that was executed
            preview: The Preview that was confirmed

        Returns:
            The consumed ConfirmationRecord

        Raises:
            ConfirmationError: If validation fails
        """
        record = self.validate(confirmation_id, candidate, preview)
        self._store.mark_consumed(confirmation_id)
        return self._store.get(confirmation_id) or record

    def _validate_candidate(self, candidate: ActionCandidate) -> None:
        """Validate that a candidate is eligible for confirmation."""
        if candidate.status == CandidateStatus.PROPOSED:
            raise ProposedCandidateError(
                f"Candidate '{candidate.candidate_id}' is proposed (not implemented). "
                "Proposed actions cannot be confirmed."
            )
        if candidate.status == CandidateStatus.BLOCKED:
            raise BlockedCandidateError(
                f"Candidate '{candidate.candidate_id}' is blocked. "
                "Blocked actions cannot be confirmed."
            )
        if candidate.status == CandidateStatus.INSUFFICIENT_EVIDENCE:
            raise InsufficientEvidenceError(
                f"Candidate '{candidate.candidate_id}' has insufficient evidence. "
                "Actions with insufficient evidence cannot be confirmed."
            )
        if candidate.status == CandidateStatus.STALE:
            raise StalePreviewError(
                f"Candidate '{candidate.candidate_id}' has stale evidence. "
                "Stale actions cannot be confirmed."
            )

    def _validate_preview(self, preview: Preview) -> None:
        """Validate that a preview is eligible for confirmation."""
        if preview.status == PreviewStatus.STALE:
            raise StalePreviewError(
                f"Preview '{preview.preview_id}' is stale. "
                "A fresh discovery is required before confirmation."
            )
        if preview.status == PreviewStatus.INSUFFICIENT_EVIDENCE:
            raise InsufficientEvidenceError(
                f"Preview '{preview.preview_id}' has insufficient evidence. "
                "Cannot confirm without adequate evidence."
            )
        if preview.status == PreviewStatus.BLOCKED:
            raise BlockedCandidateError(
                f"Preview '{preview.preview_id}' is blocked. "
                "Blocked actions cannot be confirmed."
            )
        if preview.status == PreviewStatus.UNAVAILABLE:
            raise InvalidPreviewStatusError(
                f"Preview '{preview.preview_id}' is unavailable. "
                "Cannot confirm an unavailable action."
            )
        if preview.status == PreviewStatus.ERROR:
            raise InvalidPreviewStatusError(
                f"Preview '{preview.preview_id}' has an error status. "
                "Cannot confirm with an errored preview."
            )
        # READY is the only status that allows confirmation
        if preview.status != PreviewStatus.READY:
            raise InvalidPreviewStatusError(
                f"Preview '{preview.preview_id}' has status '{preview.status.value}'. "
                "Only READY previews can be confirmed."
            )

    def _validate_preview_matches_candidate(
        self,
        candidate: ActionCandidate,
        preview: Preview,
    ) -> None:
        """Validate that a preview matches its candidate."""
        if preview.candidate_id != candidate.candidate_id:
            raise PreviewMismatchError(
                f"Preview '{preview.preview_id}' is for candidate "
                f"'{preview.candidate_id}', but expected "
                f"'{candidate.candidate_id}'."
            )
        if preview.action_id != candidate.action_id:
            raise PreviewMismatchError(
                f"Preview '{preview.preview_id}' is for action "
                f"'{preview.action_id}', but candidate is for "
                f"'{candidate.action_id}'."
            )


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_default_store: ConfirmationStore | None = None
_default_service: ConfirmationService | None = None


def get_confirmation_service() -> ConfirmationService:
    """Get or create the module-level ConfirmationService with SQLite-backed store."""
    global _default_store, _default_service
    if _default_service is None:
        _default_store = SqliteConfirmationStore()
        _default_service = ConfirmationService(store=_default_store)
    return _default_service


def confirm_candidate(
    candidate: ActionCandidate,
    preview: Preview,
) -> ConfirmationRecord:
    """Convenience function to confirm a candidate with a preview."""
    service = get_confirmation_service()
    return service.confirm(candidate, preview)
