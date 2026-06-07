"""Tests for the OpenAI-compatible AI engine (no network)."""

from __future__ import annotations

import io
import json
import urllib.error

from xsec.engines.openai_compatible import (
    PROVIDERS,
    OpenAICompatibleEngine,
    _retry_after_seconds,
    build_payload,
    extract_findings,
)
from xsec.models import Severity


def _http_error(code: int, body: str = "", headers: dict | None = None):
    return urllib.error.HTTPError(
        url="https://x/v1/chat/completions", code=code, msg="err",
        hdrs=headers or {}, fp=io.BytesIO(body.encode("utf-8")),
    )


def test_build_payload_shape():
    p = build_payload("some-model", "eval(x)", "app.py")
    assert p["model"] == "some-model"
    assert p["response_format"] == {"type": "json_object"}
    assert p["messages"][0]["role"] == "system"
    assert "JSON" in p["messages"][0]["content"]  # json_object mode needs it
    assert "app.py" in p["messages"][1]["content"]


def test_build_payload_truncates_huge_source():
    big = "x" * 200_000
    p = build_payload("m", big, "f.py")
    assert len(p["messages"][1]["content"]) < 60_000


def _resp(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


def test_extract_findings_plain_json():
    content = json.dumps({"findings": [
        {"line": 4, "severity": "high", "title": "SQLi",
         "description": "concat", "fix": "params", "cwe": "CWE-89"},
    ]})
    out = extract_findings(_resp(content), "db.py")
    assert len(out) == 1
    assert out[0].rule_id == "AI-CWE-89"
    assert out[0].severity is Severity.HIGH
    assert out[0].engine == "ai"
    assert out[0].file == "db.py"


def test_extract_findings_handles_wrapped_json():
    # some models wrap JSON in prose/markdown despite instructions
    content = "Here you go:\n```json\n{\"findings\": []}\n```"
    assert extract_findings(_resp(content), "x.py") == []


def test_extract_findings_garbage_is_empty():
    assert extract_findings(_resp("not json at all"), "x.py") == []
    assert extract_findings({}, "x.py") == []


def test_groq_preset_available_logic():
    eng = OpenAICompatibleEngine("groq", enabled=True)
    assert eng.base_url == PROVIDERS["groq"].base_url
    assert eng.model == PROVIDERS["groq"].default_model
    # no key in env/keyring -> not available, with a helpful reason
    ok, reason = eng.available()
    if not ok:  # may be False due to missing key, which is the expected path
        assert "key" in reason or "base URL" in reason


def test_disabled_engine_unavailable():
    ok, reason = OpenAICompatibleEngine("groq", enabled=False).available()
    assert ok is False and "not enabled" in reason


def test_openai_compatible_needs_base_url():
    eng = OpenAICompatibleEngine("openai-compatible", model="m", enabled=True)
    ok, reason = eng.available()
    assert ok is False and "base URL" in reason


def test_custom_base_url_is_normalized():
    eng = OpenAICompatibleEngine(
        "openai-compatible", model="m",
        base_url="http://localhost:1234/v1/", enabled=True,
    )
    assert eng.base_url == "http://localhost:1234/v1"  # trailing slash stripped


def test_retry_after_header_is_used():
    exc = _http_error(429, headers={"Retry-After": "7"})
    assert _retry_after_seconds(exc) == 7.0


def test_retry_after_parsed_from_body():
    body = json.dumps({"error": {"message": "Rate limit reached. Please try again in 3.01s."}})
    exc = _http_error(429, body=body)
    assert abs(_retry_after_seconds(exc) - 3.01) < 0.001


def test_retry_after_falls_back_to_default():
    exc = _http_error(429, body="no hint here")
    assert _retry_after_seconds(exc) == 5.0
