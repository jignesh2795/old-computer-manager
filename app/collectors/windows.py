"""Windows-specific read-only discovery helpers."""

from __future__ import annotations

import platform
import subprocess


def _powershell_json(script: str) -> object | None:
    """Run a read-only PowerShell query and parse its JSON output."""
    if platform.system() != "Windows":
        return None

    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None

    if completed.returncode != 0 or not completed.stdout.strip():
        return None

    import json

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None


def collect_os() -> object | None:
    """Collect OS/build information through CIM without changing system state."""
    return _powershell_json(
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime | "
        "ConvertTo-Json -Compress"
    )


def collect_bios() -> object | None:
    """Collect BIOS metadata through CIM."""
    return _powershell_json(
        "Get-CimInstance Win32_BIOS | "
        "Select-Object Manufacturer,SMBIOSBIOSVersion,Version,ReleaseDate,SerialNumber | "
        "ConvertTo-Json -Compress"
    )


def collect_computer_system() -> object | None:
    """Collect computer manufacturer/model metadata through CIM."""
    return _powershell_json(
        "Get-CimInstance Win32_ComputerSystem | "
        "Select-Object Manufacturer,Model,SystemType,TotalPhysicalMemory | "
        "ConvertTo-Json -Compress"
    )
