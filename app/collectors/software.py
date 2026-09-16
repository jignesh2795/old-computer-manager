"""Read-only installed software discovery for Windows."""

from __future__ import annotations

import platform

from app.collectors.result import CollectorResult
from app.collectors.windows import _powershell_json


SOFTWARE_SCRIPT = r'''
$paths = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
 Where-Object { $_.DisplayName } |
 Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation |
 Sort-Object DisplayName |
 ConvertTo-Json -Compress
'''


def collect_result() -> CollectorResult:
    if platform.system() != "Windows":
        return CollectorResult(payload=[], status="not_supported")
    result, error = _powershell_json(SOFTWARE_SCRIPT)
    if error:
        return CollectorResult(payload=[], status="failed", error_message=error)
    items = result if isinstance(result, list) else [result] if result is not None else []
    status = "ok" if items else "empty"
    return CollectorResult(payload=items, status=status)
