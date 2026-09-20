"""Read-only network health diagnostics.

Collects network adapter status, DNS configuration, and basic
connectivity indicators. Uses psutil for adapter status (no PowerShell)
and a single lightweight PowerShell query for DNS configuration.
Does NOT modify network settings, does NOT run speed tests,
does NOT change DNS or proxy configuration.
"""

from __future__ import annotations

import platform
import socket
from typing import Any

import psutil

from app.diagnostics._powershell import run_powershell
from app.diagnostics.models import DiagnosticCategory, DiagnosticResult, DiagnosticStatus

_DIAG_ID = "network_health"


def _collect_adapter_status() -> dict[str, Any]:
    """Collect network adapter status summary using psutil (no PowerShell).

    Reports up/down adapters and basic configuration.
    No raw adapter dump, no WMI queries.
    """
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        up_count = 0
        down_count = 0
        active_names: list[str] = []
        for name, stat in stats.items():
            if stat.isup:
                up_count += 1
                active_names.append(name)
            else:
                down_count += 1
        return {
            "total_adapters": len(stats),
            "up_count": up_count,
            "down_count": down_count,
            "active_names": ", ".join(active_names),
        }
    except Exception:
        return {"total_adapters": 0, "up_count": 0, "down_count": 0, "active_names": ""}


def _collect_dns_configuration() -> dict[str, Any] | None:
    """Collect DNS server configuration (single lightweight PowerShell query)."""
    if platform.system() != "Windows":
        return None

    script = (
        "$dns = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
        "Select-Object -First 5\n"
        "if ($dns) {\n"
        "    $result = @()\n"
        "    foreach ($d in $dns) {\n"
        "        $result += @{\n"
        "            interface = $d.InterfaceAlias\n"
        "            servers = ($d.ServerAddresses -join ', ')\n"
        "        }\n"
        "    }\n"
        "    ConvertTo-Json @{ configured = $true; entries = $result } -Compress\n"
        "} else {\n"
        "    ConvertTo-Json @{ configured = $false; entries = @() } -Compress\n"
        "}"
    )
    raw, error = run_powershell(script)
    if error or raw is None:
        return None

    item = raw if isinstance(raw, dict) else {}
    return {
        "configured": item.get("configured", False),
        "entries": item.get("entries", []),
    }


def _check_dns_resolution() -> dict[str, Any]:
    """Test DNS resolution for a well-known domain (no PowerShell, no network mod)."""
    try:
        result = socket.getaddrinfo("dns.google", 443, socket.AF_INET)
        return {"resolved": True, "server": "dns.google", "ip": result[0][4][0] if result else "unknown"}
    except (socket.gaierror, OSError, IndexError):
        return {"resolved": False, "server": "dns.google", "ip": None}


def collect_network_health() -> list[DiagnosticResult]:
    """Collect network health diagnostics.

    Adapter status via psutil (fast, no PowerShell).
    DNS config via single lightweight PowerShell query.
    DNS resolution via socket (fast, no external deps).
    """
    results: list[DiagnosticResult] = []

    if platform.system() != "Windows":
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_adapter_status",
            category=DiagnosticCategory.NETWORK_HEALTH,
            status=DiagnosticStatus.NOT_SUPPORTED,
            title="Network adapter status",
            summary="Network health diagnostics are not supported on this platform.",
            source="platform_check",
        ))
        return results

    # Adapter status via psutil (no PowerShell)
    adapters = _collect_adapter_status()
    total = adapters.get("total_adapters", 0)
    up = adapters.get("up_count", 0)
    down = adapters.get("down_count", 0)
    active = adapters.get("active_names", "")

    status = DiagnosticStatus.OK if up > 0 else DiagnosticStatus.WARNING
    results.append(DiagnosticResult(
        diagnostic_id=f"{_DIAG_ID}_adapter_status",
        category=DiagnosticCategory.NETWORK_HEALTH,
        status=status,
        title="Network adapter status",
        summary=f"{total} adapter(s): {up} up, {down} down. Active: {active or 'none'}",
        evidence=adapters,
        source="psutil",
    ))

    # DNS configuration (single PowerShell query)
    dns = _collect_dns_configuration()
    if dns is not None:
        configured = dns.get("configured", False)
        entries = dns.get("entries", [])
        server_count = sum(
            len(e.get("servers", "").split(",")) for e in entries if e.get("servers")
        )

        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_dns",
            category=DiagnosticCategory.NETWORK_HEALTH,
            status=DiagnosticStatus.OK if configured else DiagnosticStatus.WARNING,
            title="DNS configuration",
            summary=f"DNS {'configured' if configured else 'not configured'}: {server_count} server(s) across {len(entries)} interface(s)",
            evidence=dns,
            source="Get-DnsClientServerAddress",
        ))
    else:
        results.append(DiagnosticResult(
            diagnostic_id=f"{_DIAG_ID}_dns",
            category=DiagnosticCategory.NETWORK_HEALTH,
            status=DiagnosticStatus.UNAVAILABLE,
            title="DNS configuration",
            summary="DNS configuration could not be collected.",
            source="Get-DnsClientServerAddress",
        ))

    # DNS resolution test (socket, no PowerShell)
    dns_test = _check_dns_resolution()
    resolved = dns_test.get("resolved", False)
    results.append(DiagnosticResult(
        diagnostic_id=f"{_DIAG_ID}_dns_resolution",
        category=DiagnosticCategory.NETWORK_HEALTH,
        status=DiagnosticStatus.OK if resolved else DiagnosticStatus.WARNING,
        title="DNS resolution",
        summary=f"DNS resolution {'succeeded' if resolved else 'failed'} for dns.google ({dns_test.get('ip', 'N/A')})",
        evidence=dns_test,
        source="socket",
    ))

    return results
