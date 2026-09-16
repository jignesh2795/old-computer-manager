"""Read-only Windows service inventory."""

from __future__ import annotations

import platform

from app.collectors.result import CollectorResult
from app.collectors.windows import _powershell_json


SERVICES_SCRIPT = """
Get-CimInstance Win32_Service |
 Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
 Sort-Object Name |
 ConvertTo-Json -Compress
"""


def collect_result() -> CollectorResult:
    if platform.system() != "Windows":
        return CollectorResult(payload=[], status="not_supported")
    result, error = _powershell_json(SERVICES_SCRIPT)
    if error:
        return CollectorResult(payload=[], status="failed", error_message=error)
    items = result if isinstance(result, list) else [result] if result is not None else []
    status = "ok" if items else "empty"
    return CollectorResult(payload=items, status=status)
