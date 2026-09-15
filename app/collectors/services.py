"""Read-only Windows service inventory."""

from __future__ import annotations

import platform

from app.collectors.windows import _powershell_json


SERVICES_SCRIPT = """
Get-CimInstance Win32_Service |
 Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
 Sort-Object Name |
 ConvertTo-Json -Compress
"""


def collect() -> list[object]:
    if platform.system() != "Windows":
        return []
    result = _powershell_json(SERVICES_SCRIPT)
    if result is None:
        return []
    return result if isinstance(result, list) else [result]
