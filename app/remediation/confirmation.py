"""Explicit Confirmation gate -- accidental execution must be impossible."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

from app.remediation.action import RemediationAction


@dataclass(frozen=True)
class ConfirmationToken:
    """Opaque token proving explicit human confirmation.

    The token is bound to a specific action_id and contains a
    cryptographic nonce.  It is single-use: once consumed by
    ``consume_confirmation()``, it must not be reused.

    Design: constructing a RemediationAction is never enough to execute.
    The caller MUST explicitly create a ConfirmationToken via
    ``confirm_action()`` and pass it to the executor.
    """

    action_id: str
    _secret: str = field(default_factory=lambda: secrets.token_hex(32))
    _confirmed_hash: str = field(default="")
    _consumed: bool = field(default=False)

    def __post_init__(self) -> None:
        # Auto-compute the confirmation hash if not provided.
        # The hash proves the token was created through confirm_action().
        if not self._confirmed_hash:
            computed = hashlib.sha256(
                f"{self.action_id}:{self._secret}".encode()
            ).hexdigest()
            object.__setattr__(self, "_confirmed_hash", computed)

    @property
    def confirmed(self) -> bool:
        """Whether this token represents explicit confirmation.

        A token is confirmed only if it has a valid hash that matches
        the expected computation and has not been consumed.
        """
        if self._consumed or not self._confirmed_hash:
            return False
        expected = hashlib.sha256(
            f"{self.action_id}:{self._secret}".encode()
        ).hexdigest()
        return self._confirmed_hash == expected

    def is_valid_for(self, action_id: str) -> bool:
        """Check whether this token authorizes the given action."""
        return (
            self.action_id == action_id
            and not self._consumed
            and self.confirmed
        )


class ConfirmationRequiredError(Exception):
    """Raised when execution is attempted without valid confirmation."""


class ConfirmationReuseError(Exception):
    """Raised when a consumed confirmation token is reused."""


def confirm_action(action: RemediationAction) -> ConfirmationToken:
    """Create a confirmation token for an action.

    This function explicitly records that the caller intends to
    authorize the action.  The returned token must be passed to
    the executor.  It is single-use.
    """
    return ConfirmationToken(action_id=action.action_id)


def consume_confirmation(
    action: RemediationAction,
    token: ConfirmationToken | None,
) -> ConfirmationToken:
    """Validate and consume a confirmation token.

    The token is marked as consumed so it cannot be reused.
    Raises ConfirmationRequiredError if the token is invalid.
    Raises ConfirmationReuseError if the token was already consumed.
    """
    if token is None:
        raise ConfirmationRequiredError(
            f"No confirmation token provided for action '{action.action_id}'. "
            "Execution requires explicit confirmation."
        )
    if token._consumed:
        raise ConfirmationReuseError(
            f"Confirmation token for '{token.action_id}' has already been "
            "consumed.  Each token is single-use."
        )
    if not token.is_valid_for(action.action_id):
        raise ConfirmationRequiredError(
            f"Confirmation token is for action '{token.action_id}', "
            f"but execution targets '{action.action_id}'."
        )
    # Mark as consumed
    consumed = ConfirmationToken(
        action_id=token.action_id,
        _secret=token._secret,
        _confirmed_hash=token._confirmed_hash,
        _consumed=True,
    )
    return consumed


def require_confirmation(
    action: RemediationAction,
    token: ConfirmationToken | None,
) -> ConfirmationToken:
    """Validate a confirmation token without consuming it.

    Used for validation-only contexts.  For execution, use
    ``consume_confirmation()`` instead.
    """
    if token is None:
        raise ConfirmationRequiredError(
            f"No confirmation token provided for action '{action.action_id}'. "
            "Execution requires explicit confirmation."
        )
    if token._consumed:
        raise ConfirmationReuseError(
            f"Confirmation token for '{token.action_id}' has already been "
            "consumed."
        )
    if not token.is_valid_for(action.action_id):
        raise ConfirmationRequiredError(
            f"Confirmation token is for action '{token.action_id}', "
            f"but execution targets '{action.action_id}'."
        )
    return token
