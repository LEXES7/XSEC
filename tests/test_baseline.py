"""Tests for the baseline (snapshot existing findings, show only new ones)."""

from __future__ import annotations

from xsec.baseline import (
    build_baseline,
    filter_new,
    fingerprint,
    load_baseline,
    save_baseline,
)
from xsec.models import Finding, Severity


def _f(rule: str, file: str, line: int, snippet: str = "code") -> Finding:
    return Finding(rule, Severity.HIGH, "msg", file, line, snippet=snippet)


def test_fingerprint_ignores_line_number():
    a = _f("PY-EVAL", "app.py", 10, "eval(x)")
    b = _f("PY-EVAL", "app.py", 99, "eval(x)")  # same code, moved
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_differs_by_rule_and_snippet():
    base = _f("PY-EVAL", "app.py", 1, "eval(x)")
    assert fingerprint(base) != fingerprint(_f("PY-PICKLE", "app.py", 1, "eval(x)"))
    assert fingerprint(base) != fingerprint(_f("PY-EVAL", "app.py", 1, "eval(y)"))


def test_fingerprint_survives_directory_move():
    # uses basename, so cloning the repo elsewhere keeps the same id
    a = _f("PY-EVAL", "/home/a/app.py", 1, "eval(x)")
    b = _f("PY-EVAL", "/tmp/b/app.py", 1, "eval(x)")
    assert fingerprint(a) == fingerprint(b)


def test_filter_new_hides_known():
    known_finding = _f("PY-EVAL", "app.py", 5, "eval(x)")
    new_finding = _f("PY-PICKLE", "app.py", 8, "pickle.loads(d)")
    known = {fingerprint(known_finding)}
    out = filter_new([known_finding, new_finding], known)
    assert len(out) == 1
    assert out[0].rule_id == "PY-PICKLE"


def test_save_and_load_roundtrip(tmp_path):
    findings = [
        _f("PY-EVAL", "app.py", 1, "eval(x)"),
        _f("PY-PICKLE", "app.py", 2, "pickle.loads(d)"),
        _f("PY-EVAL", "app.py", 50, "eval(x)"),  # dupe fingerprint of the first
    ]
    path = tmp_path / ".xsec-baseline.json"
    count = save_baseline(findings, path)
    assert count == 2  # deduplicated
    loaded = load_baseline(path)
    assert loaded == set(build_baseline(findings)["fingerprints"])


def test_load_missing_is_empty(tmp_path):
    assert load_baseline(tmp_path / "nope.json") == set()


def test_load_bad_json_is_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not json")
    assert load_baseline(p) == set()
