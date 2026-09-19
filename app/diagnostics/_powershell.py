"""Shared PowerShell helper for diagnostic data collection."""

from __future__ import annotations

import json
import subprocess

from app.diagnostics.constants import POWERSHELL_TIMEOUT_SECONDS


def run_powershell(script: str) -> tuple[object | None, str | None]:
    """Execute a PowerShell command and return parsed JSON or error.

    Read-only. Does not modify system state.
    """
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=POWERSHELL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, "PowerShell command timed out"
    except OSError as exc:
        return None, f"Failed to execute PowerShell: {exc}"

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        return None, stderr or f"PowerShell exited with code {completed.returncode}"

    stdout = (completed.stdout or "").strip()
    if not stdout:
        return None, None

    try:
        return json.loads(stdout), None
    except (json.JSONDecodeError, ValueError):
        return stdout, None
