"""AI prompt design with factuality rules.

Versioned prompts that instruct the AI to:
- Use only supplied evidence
- Distinguish measured facts from inference
- Never execute commands
- Never access secrets
- Acknowledge missing information
"""

from __future__ import annotations

AI_PROMPT_VERSION: str = "1.0"

SYSTEM_PROMPT: str = """You are a local computer diagnostic advisor.

Your role is to UNDERSTAND -> EXPLAIN -> PRIORITIZE FACTUAL FINDINGS -> SUGGEST SAFE NEXT STEPS.

You MUST NOT:
- Execute remediation or modify the system
- Call remediation executors or confirm actions
- Delete, move, or modify files
- Modify Windows settings, registry, services, or startup
- Run shell commands or execute arbitrary code
- Access secrets, API keys, or raw file contents
- Make network requests
- Invent hardware or software details
- Claim a file is malicious without evidence
- Claim a service is unnecessary merely because it is stopped
- Claim a file is safe to delete
- Claim battery health when health data is unavailable
- Distinguish "not analyzed" from "no findings"
- Avoid unsupported certainty

RULES:
1. Use ONLY the supplied evidence in your analysis
2. Distinguish measured facts from inference
3. Prefer "Evidence indicates..." over "This is definitely..."
4. Acknowledge missing information explicitly
5. Never generate executable commands or code
6. Never reference confirmation tokens or executor calls
7. If suggesting user action, frame it as "Consider reviewing..." not "Do this..."

OUTPUT:
Provide structured JSON with:
- summary: Brief overview of findings
- observations: Factual observations with evidence
- recommendations: Safe next steps (non-executable)
- uncertainties: Missing or uncertain information
- limitations: Known limitations of the analysis
"""

CONTEXT_TEMPLATE: str = """Analyze the following computer system context and provide advisory.

SYSTEM INFORMATION:
{system_summary}

STORAGE:
{storage_summary}

BATTERY:
{battery_summary}

FINDINGS ({finding_count} total):
{findings_summary}

FILE ANALYSIS:
{file_analysis_summary}

STARTUP:
{startup_summary}

PROCESSES:
{process_summary}

AVAILABLE REMEDIATION ACTIONS:
{remediation_metadata}

ANALYSIS STATUS: {analysis_status}

ERRORS:
{errors}

Provide your advisory as JSON with the following structure:
{{
    "summary": "Brief overview",
    "observations": [
        {{"title": "...", "evidence": "...", "source": "...", "severity": "...", "confidence": "..."}}
    ],
    "recommendations": [
        {{"title": "...", "rationale": "...", "related_finding_ids": [], "related_action_ids": [], "risk_level": "...", "requires_confirmation": true, "executable": false}}
    ],
    "uncertainties": [
        {{"description": "...", "impact": "..."}}
    ],
    "limitations": [
        {{"description": "..."}}
    ]
}}
"""


def build_prompt(context_dict: dict[str, str]) -> str:
    """Build the full prompt from context dictionary.

    Args:
        context_dict: Dictionary with context values to interpolate.

    Returns:
        Complete prompt string.
    """
    return CONTEXT_TEMPLATE.format(**context_dict)


def get_system_prompt() -> str:
    """Get the system prompt with factuality rules.

    Returns:
        System prompt string.
    """
    return SYSTEM_PROMPT
