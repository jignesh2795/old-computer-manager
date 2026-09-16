"""Read-only Windows startup entry discovery."""

from __future__ import annotations

import platform

from app.collectors.result import CollectorResult
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


def collect_result() -> CollectorResult:
    if platform.system() != "Windows":
        return CollectorResult(payload=[], status="not_supported")
    result, error = _powershell_json(STARTUP_SCRIPT)
    if error:
        return CollectorResult(payload=[], status="failed", error_message=error)
    items = result if isinstance(result, list) else [result] if result is not None else []
    status = "ok" if items else "empty"
    return CollectorResult(payload=items, status=status)
