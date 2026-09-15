"""Read-only Windows scheduled-task inventory."""

from __future__ import annotations

import platform

from app.collectors.windows import _powershell_json


TASKS_SCRIPT = r'''
Get-ScheduledTask -ErrorAction SilentlyContinue |
 Select-Object TaskName,TaskPath,State,Author,Description |
 Sort-Object TaskPath,TaskName |
 ConvertTo-Json -Compress
'''


def collect() -> list[object]:
    if platform.system() != "Windows":
        return []
    result = _powershell_json(TASKS_SCRIPT)
    if result is None:
        return []
    return result if isinstance(result, list) else [result]
