"""Read-only Windows scheduled-task inventory."""

from __future__ import annotations

import platform

from app.collectors.result import CollectorResult
from app.collectors.windows import _powershell_json


TASKS_SCRIPT = r'''
Get-ScheduledTask -ErrorAction SilentlyContinue |
 Select-Object TaskName,TaskPath,State,Author,Description |
 Sort-Object TaskPath,TaskName |
 ConvertTo-Json -Compress
'''


def collect_result() -> CollectorResult:
    if platform.system() != "Windows":
        return CollectorResult(payload=[], status="not_supported")
    result, error = _powershell_json(TASKS_SCRIPT)
    if error:
        return CollectorResult(payload=[], status="failed", error_message=error)
    items = result if isinstance(result, list) else [result] if result is not None else []
    status = "ok" if items else "empty"
    return CollectorResult(payload=items, status=status)
