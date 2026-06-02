"""Tests for the HTML report."""

from __future__ import annotations

from xsec.models import Finding, ScanResult, Severity
from xsec.report.html import to_html


def _result_with_findings() -> ScanResult:
    r = ScanResult(files_scanned=2)
    r.add([
        Finding("PY-EVAL", Severity.HIGH, "eval is dangerous", "a.py", 3,
                engine="sast", fix="Avoid eval", snippet="eval(x)"),
        Finding("AI-CWE-89", Severity.CRITICAL, "SQL injection", "b.py", 9,
                engine="ai"),
    ])
    return r


def test_html_contains_findings():
    out = to_html(_result_with_findings())
    assert out.startswith("<!doctype html>")
    assert "PY-EVAL" in out and "AI-CWE-89" in out
    assert "SQL injection" in out
    assert "a.py" in out and "b.py" in out
    # Critical sorts above high.
    assert out.index("AI-CWE-89") < out.index("PY-EVAL")


def test_html_escapes_content():
    r = ScanResult(files_scanned=1)
    r.add([Finding("X", Severity.LOW, "<script>alert(1)</script>", "x.py", 1)])
    out = to_html(r)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out


def test_html_clean_state():
    out = to_html(ScanResult(files_scanned=5))
    assert "No findings" in out
    assert "<!doctype html>" in out
