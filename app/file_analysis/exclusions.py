"""Exclusion engine for file scanning.

Excludes symlinks, junctions, system-critical paths, quarantine directories,
and inaccessible items. All exclusions are explicit and recorded in scan stats.
"""

from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath


# -- System-critical directories that must never be scanned ----------------
# These are dangerous to scan on Windows and provide no useful intelligence.

_SYSTEM_CRITICAL_PATHS: set[str] = {
    r"C:\Windows\System32",
    r"C:\Windows\WinSxS",
    r"C:\Windows\Logs",
    r"C:\Windows\Temp",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    r"C:\Recovery",
    r"C:\$Recycle.Bin",
    r"C:\System Volume Information",
    r"C:\Boot",
    r"C:\bootmgr",
}

# Normalize to lowercase for comparison
_SYSTEM_CRITICAL_LOW: set[str] = {p.lower().rstrip("\\/") for p in _SYSTEM_CRITICAL_PATHS}


# -- Quarantine directory exclusion ----------------------------------------

_QUARANTINE_DIR_NAME = "quarantine"
_APP_DATA_DIR_NAME = ".old-computer-manager"


def is_excluded_path(path: Path, scan_root: Path) -> tuple[bool, str]:
    """Check whether a path should be excluded from scanning.

    Returns (is_excluded, reason). If not excluded, reason is ''.
    """
    resolved = path.resolve()
    resolved_str = str(resolved)

    # -- Check against system-critical paths -------------------------------
    for critical in _SYSTEM_CRITICAL_LOW:
        try:
            resolved.relative_to(critical)
            return True, f"system-critical path: {critical}"
        except ValueError:
            continue

    # -- Check quarantine directory ----------------------------------------
    parts = resolved.parts
    for i, part in enumerate(parts):
        if part.lower() == _APP_DATA_DIR_NAME:
            # Check if 'quarantine' follows
            if i + 1 < len(parts) and parts[i + 1].lower() == _QUARANTINE_DIR_NAME:
                return True, "quarantine directory"

    # -- Check scan root containment ---------------------------------------
    try:
        resolved.relative_to(scan_root.resolve())
    except ValueError:
        return True, "outside scan root"

    return False, ""


def is_excluded_entry(
    entry_name: str,
    entry_path: Path,
    is_symlink: bool,
    is_dir: bool,
    scan_root: Path,
) -> tuple[bool, str]:
    """Check whether a directory entry should be skipped.

    Returns (is_excluded, reason).
    """
    # -- Symlinks always excluded ------------------------------------------
    if is_symlink:
        return True, "symlink"

    # -- Path-level exclusions ---------------------------------------------
    excluded, reason = is_excluded_path(entry_path, scan_root)
    if excluded:
        return True, reason

    return False, ""


def validate_scan_root(root: str | Path) -> Path:
    """Validate and resolve a scan root directory.

    Raises ValueError if the root is invalid or dangerous.
    Returns the resolved Path.
    """
    path = Path(root).resolve()

    if not path.exists():
        raise ValueError(f"Path does not exist: {path}")

    if not path.is_dir():
        raise ValueError(f"Path is not a directory: {path}")

    # Check against system-critical paths
    path_str = str(path).lower().rstrip("\\/")
    for critical in _SYSTEM_CRITICAL_LOW:
        if path_str == critical or path_str.startswith(critical + "\\"):
            raise ValueError(
                f"Refusing to scan system-critical path: {path}. "
                f"This directory is excluded for safety."
            )

    return path
