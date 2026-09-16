"""Windows-specific read-only discovery helpers."""

from __future__ import annotations

import json
import platform
import subprocess

from app.collectors.result import CollectorResult


def _powershell_json(script: str) -> tuple[object | None, str | None]:
    """Run a read-only PowerShell query and parse its JSON output.

    Returns a tuple of (result, error_message). On success error_message is None.
    On failure result is None and error_message describes the problem.
    """
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        return None, "powershell.exe not found"
    except subprocess.TimeoutExpired:
        return None, "PowerShell command timed out after 15s"
    except (subprocess.SubprocessError, OSError) as exc:
        return None, f"PowerShell subprocess error: {exc}"

    if completed.returncode != 0:
        return None, f"PowerShell exited with code {completed.returncode}"
    if not completed.stdout.strip():
        return None, "PowerShell returned empty output"

    try:
        return json.loads(completed.stdout, strict=False), None
    except json.JSONDecodeError as exc:
        return None, f"JSON parse error: {exc}"


def collect_os() -> CollectorResult:
    """Collect OS/build information through CIM without changing system state."""
    if platform.system() != "Windows":
        return CollectorResult(payload=None, status="not_supported")
    result, error = _powershell_json(
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime | "
        "ConvertTo-Json -Compress"
    )
    if error:
        return CollectorResult(payload=None, status="failed", error_message=error)
    return CollectorResult(payload=result, status="ok")


def collect_bios() -> CollectorResult:
    """Collect BIOS metadata through CIM."""
    if platform.system() != "Windows":
        return CollectorResult(payload=None, status="not_supported")
    result, error = _powershell_json(
        "Get-CimInstance Win32_BIOS | "
        "Select-Object Manufacturer,SMBIOSBIOSVersion,Version,ReleaseDate,SerialNumber | "
        "ConvertTo-Json -Compress"
    )
    if error:
        return CollectorResult(payload=None, status="failed", error_message=error)
    return CollectorResult(payload=result, status="ok")


def collect_computer_system() -> CollectorResult:
    """Collect computer manufacturer/model metadata through CIM."""
    if platform.system() != "Windows":
        return CollectorResult(payload=None, status="not_supported")
    result, error = _powershell_json(
        "Get-CimInstance Win32_ComputerSystem | "
        "Select-Object Manufacturer,Model,SystemType,TotalPhysicalMemory | "
        "ConvertTo-Json -Compress"
    )
    if error:
        return CollectorResult(payload=None, status="failed", error_message=error)
    return CollectorResult(payload=result, status="ok")
