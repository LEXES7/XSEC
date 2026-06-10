"""AI review via any OpenAI-compatible chat API.

This is the **free** path: providers like Groq and OpenRouter expose an
OpenAI-compatible ``/chat/completions`` endpoint with a free tier and a free API
key, so you can run AI review at no cost. The same engine works with any other
OpenAI-compatible endpoint via a custom base URL.

Honest tradeoff: unlike a local model, these providers receive your code, and
free tiers have rate limits. It stays opt-in, exactly like the Anthropic engine.

No SDK dependency: an OpenAI-compatible call is a plain HTTPS POST, so we use
stdlib ``urllib`` (the same approach as the dependency scanner).
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from xsec import __version__
from xsec.engines._ai_common import (
    JSON_SHAPE_INSTRUCTION,
    MAX_CHARS,
    SYSTEM_PROMPT,
    AiReviewError,
    parse_findings,
    review_many,
)
from xsec.engines.base import Engine
from xsec.models import Finding
from xsec.netutil import ssl_context
from xsec.secrets import get_api_key

_TIMEOUT = 60
_MAX_RETRIES = 4          # retry a rate-limited request up to this many times
_MAX_RETRY_WAIT = 30.0    # never wait longer than this between attempts (seconds)
_DEFAULT_RETRY_WAIT = 5.0  # fallback when the provider gives no hint


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    default_model: str


# free-tier-friendly presets. "openai-compatible" is filled in from CLI/config.
PROVIDERS = {
    "groq": Provider(
        "groq", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile",
    ),
    "openrouter": Provider(
        "openrouter", "https://openrouter.ai/api/v1",
        "meta-llama/llama-3.3-70b-instruct:free",
    ),
}


def build_payload(model: str, source: str, path: Path | str) -> dict:
    """Build the chat-completions request body. Pure, so it's unit-testable."""
    user = f"File: {path}\n\n```\n{source[:MAX_CHARS]}\n```"
    return {
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT + JSON_SHAPE_INSTRUCTION},
            {"role": "user", "content": user},
        ],
    }


def extract_findings(resp_json: dict, path: Path | str) -> list[Finding]:
    """Pull findings out of an OpenAI-compatible response. Pure / testable.

    Tolerates the model wrapping JSON in stray text by extracting the first
    ``{ ... }`` block if a direct parse fails.
    """
    try:
        content = resp_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return []
    data = _loads_lenient(content)
    if data is None:
        return []
    return parse_findings(data, str(path))


def _loads_lenient(content: str) -> dict | None:
    if not content:
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    # fall back to the outermost {...} span
    start, end = content.find("{"), content.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(content[start:end + 1])
        except json.JSONDecodeError:
            return None
    return None


class OpenAICompatibleEngine(Engine):
    name = "ai"

    def __init__(
        self,
        provider: str,
        model: str | None = None,
        base_url: str | None = None,
        enabled: bool = True,
        cache: bool = True,
    ) -> None:
        self.enabled = enabled
        self.provider = provider
        preset = PROVIDERS.get(provider)
        self.base_url = (base_url or (preset.base_url if preset else "")).rstrip("/")
        self.model = model or (preset.default_model if preset else None)
        self.cache = cache
        self.errors: list[str] = []

    def available(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "not enabled (pass --ai)"
        if not self.base_url:
            return False, (
                f"no base URL for provider '{self.provider}' "
                "(use a known provider or pass --ai-base-url)"
            )
        if not self.model:
            return False, f"no model set for provider '{self.provider}' (pass --ai-model)"
        if not get_api_key(self.provider):
            return False, (
                f"no API key (run: xsec key set --provider {self.provider})"
            )
        return True, ""

    def analyze(self, files: list[Path]) -> list[Finding]:
        key = get_api_key(self.provider)

        def review_one(path: Path, source: str) -> list[Finding]:
            try:
                return self._review_with_retry(key, path, source)
            except urllib.error.HTTPError as exc:
                # the provider explains the real reason in the response body;
                # surface it instead of a bare "HTTP Error 403: Forbidden"
                raise AiReviewError(_http_error_detail(exc)) from exc
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                raise AiReviewError(str(exc)) from exc

        return review_many(
            files, f"{self.provider}|{self.base_url}|{self.model}",
            review_one, self.errors, use_cache=self.cache,
        )

    def _review_with_retry(self, key: str, path: Path, source: str) -> list[Finding]:
        """Call the provider, retrying on 429 (rate limit) per its wait hint.

        Free tiers throttle by tokens/minute; the provider tells us how long to
        wait, so honoring that turns a wall of errors into a slightly slower scan
        that still completes.
        """
        for attempt in range(_MAX_RETRIES + 1):
            try:
                return self._review(key, path, source)
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < _MAX_RETRIES:
                    wait = min(_retry_after_seconds(exc), _MAX_RETRY_WAIT)
                    time.sleep(wait)
                    continue
                raise
        return []

    def _review(self, key: str, path: Path, source: str) -> list[Finding]:
        body = json.dumps(build_payload(self.model, source, path)).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}",
                # some providers sit behind Cloudflare, which blocks the default
                # python-urllib agent (error 1010); send a normal UA
                "User-Agent": f"xsec/{__version__}",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=ssl_context()) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return extract_findings(payload, path)


def _retry_after_seconds(exc: urllib.error.HTTPError) -> float:
    """How long to wait before retrying a 429, from the response.

    Prefers the standard ``Retry-After`` header; otherwise parses the
    "try again in 3.01s" hint many OpenAI-compatible providers put in the body.
    Falls back to a sane default.
    """
    header = exc.headers.get("Retry-After") if exc.headers else None
    if header:
        try:
            return max(0.0, float(header))
        except ValueError:
            pass
    try:
        body = exc.read().decode("utf-8", errors="replace")
        m = re.search(r"try again in\s+([0-9.]+)\s*s", body)
        if m:
            return max(0.0, float(m.group(1)))
    except Exception:
        pass
    return _DEFAULT_RETRY_WAIT


def _http_error_detail(exc: urllib.error.HTTPError) -> str:
    """Pull the provider's error message out of an HTTPError body.

    OpenAI-compatible errors look like {"error": {"message": "..."}}; fall back
    to the raw body or the status line if we can't parse it.
    """
    status = f"HTTP {exc.code}"
    try:
        body = exc.read().decode("utf-8", errors="replace")
    except Exception:
        return f"{status} {exc.reason}"
    try:
        data = json.loads(body)
        msg = data.get("error", {}).get("message") if isinstance(data, dict) else None
        if msg:
            return f"{status}: {msg}"
    except json.JSONDecodeError:
        pass
    return f"{status}: {body[:300]}" if body.strip() else f"{status} {exc.reason}"
