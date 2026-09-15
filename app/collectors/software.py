"""Read-only installed software discovery for Windows."""

from __future__ import annotations

import platform

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


def collect() -> list[object]:
    if platform.system() != "Windows":
        return []
    result = _powershell_json(SOFTWARE_SCRIPT)
    if result is None:
        return []
    return result if isinstance(result, list) else [result]
