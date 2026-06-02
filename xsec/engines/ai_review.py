"""AI review engine: ask Claude to look for vulnerabilities.

Rules only catch what we wrote a rule for. This sends the file to Claude,
which can spot logic bugs, broken auth, and unsafe data flow in any language.
It's opt-in (--ai) and skips itself if there's no API key.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from xsec.engines.base import Engine
from xsec.models import Finding, Severity

# default to the strongest model; drop to sonnet via --ai-model for big trees
DEFAULT_MODEL = "claude-opus-4-8"
# only send the head of very large files
_MAX_CHARS = 48_000

_SYSTEM_PROMPT = """\
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

# structured-output schema. it needs additionalProperties:false and every key
# required, so cwe/fix come back as "" sometimes - parse_findings handles that.
_FINDINGS_SCHEMA = {
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


class AiReviewEngine(Engine):
    name = "ai"

    def __init__(self, enabled: bool = False, model: str | None = None) -> None:
        self.enabled = enabled
        self.model = model or os.environ.get("XSEC_AI_MODEL") or DEFAULT_MODEL
        self._client = None
        # per-file failures, surfaced by the CLI without stopping the scan
        self.errors: list[str] = []

    def available(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "not enabled (pass --ai)"
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "anthropic package not installed (pip install 'xsec[ai]')"
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False, "ANTHROPIC_API_KEY not set"
        return True, ""

    def _get_client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic()
        return self._client

    def analyze(self, files: list[Path]) -> list[Finding]:
        import anthropic

        findings: list[Finding] = []
        client = self._get_client()
        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            try:
                findings.extend(self._review(client, path, source[:_MAX_CHARS]))
            except anthropic.APIError as exc:
                self.errors.append(f"AI review failed for {path}: {exc}")
        return findings

    def _review(self, client, path: Path, source: str) -> list[Finding]:
        user = f"File: {path}\n\n```\n{source}\n```"
        resp = client.messages.create(
            model=self.model,
            max_tokens=8000,
            thinking={"type": "adaptive"},
            system=[{
                "type": "text",
                "text": _SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }],
            output_config={
                "effort": "high",
                "format": {"type": "json_schema", "schema": _FINDINGS_SCHEMA},
            },
            messages=[{"role": "user", "content": user}],
        )
        # the format setting guarantees a text block of valid JSON
        text = next((b.text for b in resp.content if b.type == "text"), None)
        if not text:
            return []
        return parse_findings(json.loads(text), str(path))
