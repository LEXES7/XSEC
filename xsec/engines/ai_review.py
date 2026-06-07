"""AI review engine: ask Claude to look for vulnerabilities.

Rules only catch what we wrote a rule for. This sends the file to Claude,
which can spot logic bugs, broken auth, and unsafe data flow in any language.
It's opt-in (--ai) and skips itself if there's no API key.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from xsec.engines._ai_common import (
    FINDINGS_SCHEMA,
    MAX_CHARS,
    SYSTEM_PROMPT,
    parse_findings,
)
from xsec.engines.base import Engine
from xsec.models import Finding
from xsec.secrets import get_api_key

# default to the strongest model; drop to sonnet via --ai-model for big trees
DEFAULT_MODEL = "claude-opus-4-8"

# kept as module-level names for backward compatibility (tests import these)
_MAX_CHARS = MAX_CHARS
_SYSTEM_PROMPT = SYSTEM_PROMPT
_FINDINGS_SCHEMA = FINDINGS_SCHEMA

__all__ = ["AiReviewEngine", "parse_findings", "DEFAULT_MODEL"]


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
        if not get_api_key():
            return False, (
                "no Anthropic API key. Use Claude (run: xsec key set), or scan "
                "free with Groq (--ai-provider groq, free key at console.groq.com)"
            )
        return True, ""

    def _get_client(self):
        if self._client is None:
            import anthropic
            # pass the key explicitly so it works from the OS keyring too,
            # not just the environment variable
            self._client = anthropic.Anthropic(api_key=get_api_key())
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
