"""Read-only Windows startup entry discovery."""

from __future__ import annotations

import platform

from app.collectors.windows import _powershell_json


STARTUP_SCRIPT = r'''
$items = @()
$runPaths = @(
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($path in $runPaths) {
 if (Test-Path $path) {
  $props = Get-ItemProperty $path
  foreach ($p in $props.PSObject.Properties) {
   if ($p.Name -notmatch '^PS') {
    $items += [pscustomobject]@{Location=$path;Name=$p.Name;Command=[string]$p.Value}
   }
  }
 }
}
$items | Sort-Object Location,Name | ConvertTo-Json -Compress
'''


def collect() -> list[object]:
    if platform.system() != "Windows":
        return []
    result = _powershell_json(STARTUP_SCRIPT)
    if result is None:
        return []
    return result if isinstance(result, list) else [result]
