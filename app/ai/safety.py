"""AI response safety validator.

Detects prohibited content such as:
- cmd.exe instructions
- PowerShell execution strings
- Shell pipelines
- Registry modification commands
- Destructive filesystem commands
- Arbitrary executable paths
- Direct remediation API calls

The real security boundary is that the AI has no executor access.
This is an additional safety layer.
"""

from __future__ import annotations

import re
from typing import Any


# Patterns indicating executable content
EXECUTABLE_PATTERNS: list[re.Pattern] = [
    # Shell commands
    re.compile(r"cmd\.exe\s*/[cC]", re.IGNORECASE),
    re.compile(r"powershell\.exe", re.IGNORECASE),
    re.compile(r"pwsh\.exe", re.IGNORECASE),
    re.compile(r"/bin/(?:ba)?sh", re.IGNORECASE),
    re.compile(r"bash\s+-[cC]", re.IGNORECASE),
    # Registry
    re.compile(r"reg\s+(?:add|delete|edit|import|export)", re.IGNORECASE),
    re.compile(r"regedit\.exe", re.IGNORECASE),
    re.compile(r"HK(?:LM|CU|CR|U|CC)\\", re.IGNORECASE),
    # File operations
    re.compile(r"(?:Remove|Delete)-Item", re.IGNORECASE),
    re.compile(r"rmdir\s+/[sSqQ]", re.IGNORECASE),
    re.compile(r"del\s+/[fFqQsS]", re.IGNORECASE),
    re.compile(r"rm\s+-rf?\s+", re.IGNORECASE),
    # Network
    re.compile(r"Invoke-WebRequest", re.IGNORECASE),
    re.compile(r"curl\s+", re.IGNORECASE),
    re.compile(r"wget\s+", re.IGNORECASE),
    # Services
    re.compile(r"sc\s+(?:create|delete|config|start|stop)", re.IGNORECASE),
    re.compile(r"Set-Service", re.IGNORECASE),
    # Scheduled tasks
    re.compile(r"schtasks\s+/(?:create|delete|change)", re.IGNORECASE),
    # Process execution
    re.compile(r"Start-Process\s+", re.IGNORECASE),
    re.compile(r"Start-Job\s+", re.IGNORECASE),
    re.compile(r"Invoke-Command\s+", re.IGNORECASE),
    # Python execution
    re.compile(r"subprocess\.(?:call|run|Popen)", re.IGNORECASE),
    re.compile(r"os\.(?:system|popen)", re.IGNORECASE),
]

# Patterns indicating direct remediation API calls
REMEDIATION_PATTERNS: list[re.Pattern] = [
    re.compile(r"executor\.(?:execute|run)", re.IGNORECASE),
    re.compile(r"confirm_action", re.IGNORECASE),
    re.compile(r"rollback_quarantine", re.IGNORECASE),
    re.compile(r"execute_quarantine", re.IGNORECASE),
    re.compile(r"QuarantineExecutor", re.IGNORECASE),
]

# Dangerous file paths
DANGEROUS_PATHS: list[re.Pattern] = [
    re.compile(r"C:\\Windows\\System32", re.IGNORECASE),
    re.compile(r"C:\\Windows\\SysWOW64", re.IGNORECASE),
    re.compile(r"C:\\Windows\\WinSxS", re.IGNORECASE),
    re.compile(r"/etc/(?:passwd|shadow|sudoers)", re.IGNORECASE),
]


class SafetyViolation(Exception):
    """Raised when AI output contains prohibited content."""
    pass


def validate_ai_output(output: str) -> tuple[bool, list[str]]:
    """Validate AI output for prohibited content.

    Args:
        output: The AI-generated output to validate.

    Returns:
        Tuple of (is_safe, list_of_violations).
    """
    violations = []

    # Check for executable patterns
    for pattern in EXECUTABLE_PATTERNS:
        matches = pattern.findall(output)
        if matches:
            violations.append(f"Executable pattern detected: {pattern.pattern}")

    # Check for remediation API patterns
    for pattern in REMEDIATION_PATTERNS:
        matches = pattern.findall(output)
        if matches:
            violations.append(f"Remediation API pattern detected: {pattern.pattern}")

    # Check for dangerous paths
    for pattern in DANGEROUS_PATHS:
        matches = pattern.findall(output)
        if matches:
            violations.append(f"Dangerous path detected: {pattern.pattern}")

    return len(violations) == 0, violations


def validate_recommendation(recommendation: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate a single recommendation for safety.

    Args:
        recommendation: Recommendation dictionary to validate.

    Returns:
        Tuple of (is_safe, list_of_violations).
    """
    violations = []

    # Check executable flag
    if recommendation.get("executable") is True:
        violations.append("Recommendation has executable=True (must be False)")

    # Check for executable content in title/rationale
    for field_name in ["title", "rationale"]:
        value = recommendation.get(field_name, "")
        if isinstance(value, str):
            is_safe, field_violations = validate_ai_output(value)
            if not is_safe:
                violations.extend([f"{field_name}: {v}" for v in field_violations])

    return len(violations) == 0, violations


def validate_advisory(advisory_dict: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate a complete advisory for safety.

    Args:
        advisory_dict: Advisory dictionary to validate.

    Returns:
        Tuple of (is_safe, list_of_violations).
    """
    violations = []

    # Validate summary
    summary = advisory_dict.get("summary", "")
    if isinstance(summary, str):
        is_safe, summary_violations = validate_ai_output(summary)
        if not is_safe:
            violations.extend([f"summary: {v}" for v in summary_violations])

    # Validate observations
    for i, obs in enumerate(advisory_dict.get("observations", [])):
        for field_name in ["title", "evidence"]:
            value = obs.get(field_name, "")
            if isinstance(value, str):
                is_safe, field_violations = validate_ai_output(value)
                if not is_safe:
                    violations.extend([f"observations[{i}].{field_name}: {v}" for v in field_violations])

    # Validate recommendations
    for i, rec in enumerate(advisory_dict.get("recommendations", [])):
        is_safe, rec_violations = validate_recommendation(rec)
        if not is_safe:
            violations.extend([f"recommendations[{i}]: {v}" for v in rec_violations])

    return len(violations) == 0, violations
