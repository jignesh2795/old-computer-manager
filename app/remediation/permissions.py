"""Permission Check -- platform abstraction for privilege detection."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class PrivilegeStatus:
    """Current privilege state of the running process.

    Attributes:
        is_admin: Whether the process has administrator/root privileges.
        platform: The OS platform detected.
        method: The detection method used.
    """

    is_admin: bool
    platform: str
    method: str


def check_admin_privileges() -> PrivilegeStatus:
    """Detect whether the current process has elevated privileges.

    This is a READ-ONLY check.  It does NOT elevate privileges,
    launch UAC, or modify anything.

    On non-Windows systems, returns is_admin based on effective uid.
    On Windows, uses ctypes to check group membership without elevation.
    Safe to call from tests on any platform.
    """
    current_platform = sys.platform

    if current_platform == "win32":
        return _check_windows()
    elif current_platform in ("linux", "darwin"):
        return _check_unix()
    else:
        return PrivilegeStatus(
            is_admin=False,
            platform=current_platform,
            method="unsupported_platform",
        )


def _check_windows() -> PrivilegeStatus:
    """Check admin status on Windows without elevation."""
    try:
        import ctypes
        # This is a safe, read-only API call.  It does not modify anything.
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return PrivilegeStatus(
            is_admin=is_admin,
            platform="win32",
            method="ctypes.windll.shell32.IsUserAnAdmin",
        )
    except Exception:
        return PrivilegeStatus(
            is_admin=False,
            platform="win32",
            method="fallback",
        )


def _check_unix() -> PrivilegeStatus:
    """Check admin status on Unix-like systems."""
    is_admin = os.geteuid() == 0
    return PrivilegeStatus(
        is_admin=is_admin,
        platform=sys.platform,
        method="os.geteuid",
    )
