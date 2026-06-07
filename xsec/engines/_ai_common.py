"""Shared, provider-neutral pieces for the AI review engines.

Both the Anthropic engine and the OpenAI-compatible engine ask a model the same
question (find vulnerabilities, return structured JSON) and turn the same JSON
shape into Findings. That common ground lives here so neither engine duplicates
it.
"""

from __future__ import annotations

from xsec.models import Finding, Severity

# only send the head of very large files
MAX_CHARS = 48_000

SYSTEM_PROMPT = """\
You are a senior application-security engineer reviewing source code for \
vulnerabilities. The code was often written by an AI assistant, which tends to \
introduce: command/SQL injection, unsafe deserialization, missing authn/authz \
checks, hardcoded secrets, SSRF, path traversal, weak crypto, unvalidated \
input reaching dangerous sinks, and race conditions.

Review the provided file and report only *genuine, actionable* security issues. \
Do not report style, performance, or speculative concerns. For each issue give \
the 1-based line number, a severity, a short title, a clear explanation of the \
risk, and a concrete fix. Prefer precision over recall: a false positive costs \
the user trust. If the file has no real security issues, return an empty list.\
"""

# extra instruction for providers that only do generic JSON mode (no schema):
# they need the word "JSON" and an explicit shape in the prompt.
JSON_SHAPE_INSTRUCTION = """\

Respond with ONLY a JSON object of this exact shape (no prose, no markdown):
{"findings": [{"line": <int>, "severity": "critical|high|medium|low|info", \
"title": <string>, "description": <string>, "fix": <string>, "cwe": <string>}]}
If there are no issues, respond with {"findings": []}.\
"""

# JSON Schema used by providers that support structured output (Anthropic).
FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "line": {"type": "integer"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "fix": {"type": "string"},
                    "cwe": {"type": "string"},
                },
                "required": ["line", "severity", "title", "description", "fix", "cwe"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def parse_findings(raw: dict, file: str) -> list[Finding]:
    """Turn the model's JSON into Findings (skips junk items)."""
    out: list[Finding] = []
    for item in raw.get("findings", []):
        if not isinstance(item, dict) or "title" not in item:
            continue
        sev = _SEV_MAP.get(str(item.get("severity", "")).lower(), Severity.MEDIUM)
        cwe = item.get("cwe") or None
        rule_id = f"AI-{cwe}" if cwe else "AI-REVIEW"
        msg = item["title"]
        if item.get("description"):
            msg = f"{item['title']} - {item['description']}"
        out.append(Finding(
            rule_id=rule_id,
            severity=sev,
            message=msg,
            file=file,
            line=int(item.get("line", 0) or 0),
            engine="ai",
            fix=item.get("fix"),
        ))
    return out
