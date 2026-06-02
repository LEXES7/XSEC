"""AI engine tests (no network - we test the JSON parsing directly)."""

from __future__ import annotations

from xsec.engines.ai_review import AiReviewEngine, parse_findings
from xsec.models import Severity


def test_parse_basic():
    raw = {"findings": [
        {"line": 12, "severity": "high", "title": "SQL injection",
         "description": "User input concatenated into a query.",
         "fix": "Use parameterized queries.", "cwe": "CWE-89"},
        {"line": 3, "severity": "low", "title": "Weak hash",
         "description": "MD5 used."},
    ]}
    findings = parse_findings(raw, "app.py")
    assert len(findings) == 2

    sqli = findings[0]
    assert sqli.severity is Severity.HIGH
    assert sqli.rule_id == "AI-CWE-89"
    assert sqli.engine == "ai"
    assert sqli.line == 12
    assert "SQL injection" in sqli.message and "concatenated" in sqli.message
    assert sqli.fix == "Use parameterized queries."

    assert findings[1].rule_id == "AI-REVIEW"  # no cwe -> generic id


def test_parse_is_defensive():
    raw = {"findings": [
        {"severity": "high"},                 # missing title -> skipped
        "not a dict",                         # wrong type -> skipped
        {"title": "ok", "severity": "weird"},  # bad severity -> defaults MEDIUM
    ]}
    findings = parse_findings(raw, "x.py")
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].line == 0


def test_empty_findings():
    assert parse_findings({"findings": []}, "x.py") == []
    assert parse_findings({}, "x.py") == []


def test_disabled_engine_is_unavailable():
    ok, reason = AiReviewEngine(enabled=False).available()
    assert ok is False and "not enabled" in reason


def test_model_default_and_override(monkeypatch):
    monkeypatch.delenv("XSEC_AI_MODEL", raising=False)
    assert AiReviewEngine().model == "claude-opus-4-8"
    assert AiReviewEngine(model="claude-sonnet-4-6").model == "claude-sonnet-4-6"
    monkeypatch.setenv("XSEC_AI_MODEL", "claude-haiku-4-5")
    assert AiReviewEngine().model == "claude-haiku-4-5"
