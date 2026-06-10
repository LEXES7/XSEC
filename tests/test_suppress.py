"""Inline `xsec: ignore` suppression tests."""

from __future__ import annotations

from pathlib import Path

from xsec.models import Finding, Severity
from xsec.suppress import filter_suppressed


def _finding(file: str, line: int, rule_id: str = "PY-EVAL") -> Finding:
    return Finding(
        rule_id=rule_id, severity=Severity.HIGH, message="m", file=file, line=line,
    )


def _write(tmp_path: Path, code: str) -> str:
    f = tmp_path / "sample.py"
    f.write_text(code)
    return str(f)


def test_bare_ignore_suppresses_everything_on_the_line(tmp_path):
    path = _write(tmp_path, "eval(x)  # xsec: ignore\n")
    kept, n = filter_suppressed([_finding(path, 1)])
    assert kept == [] and n == 1


def test_scoped_ignore_matches_rule(tmp_path):
    path = _write(tmp_path, "eval(x)  # xsec: ignore[PY-EVAL]\n")
    kept, n = filter_suppressed([_finding(path, 1)])
    assert kept == [] and n == 1


def test_scoped_ignore_other_rule_does_not_match(tmp_path):
    path = _write(tmp_path, "eval(x)  # xsec: ignore[PY-PICKLE]\n")
    kept, n = filter_suppressed([_finding(path, 1)])
    assert len(kept) == 1 and n == 0


def test_multiple_rules_in_one_marker(tmp_path):
    path = _write(tmp_path, "eval(x)  # xsec: ignore[PY-PICKLE, PY-EVAL]\n")
    kept, n = filter_suppressed([_finding(path, 1)])
    assert kept == [] and n == 1


def test_comment_line_above_suppresses(tmp_path):
    path = _write(tmp_path, "# xsec: ignore[PY-EVAL]\neval(x)\n")
    kept, n = filter_suppressed([_finding(path, 2)])
    assert kept == [] and n == 1


def test_code_line_above_does_not_suppress(tmp_path):
    # the marker on line 1 belongs to line 1's code, not to line 2
    path = _write(tmp_path, "foo()  # xsec: ignore\neval(x)\n")
    kept, n = filter_suppressed([_finding(path, 2)])
    assert len(kept) == 1 and n == 0


def test_js_style_comment(tmp_path):
    f = tmp_path / "sample.js"
    f.write_text("eval(x);  // xsec: ignore[JS-EVAL]\n")
    kept, n = filter_suppressed([_finding(str(f), 1, "JS-EVAL")])
    assert kept == [] and n == 1


def test_unsuppressed_findings_are_kept(tmp_path):
    path = _write(tmp_path, "eval(x)\n")
    kept, n = filter_suppressed([_finding(path, 1)])
    assert len(kept) == 1 and n == 0


def test_line_zero_findings_pass_through(tmp_path):
    kept, n = filter_suppressed([_finding("requirements.txt", 0, "DEP-VULN")])
    assert len(kept) == 1 and n == 0


def test_missing_file_keeps_finding(tmp_path):
    kept, n = filter_suppressed([_finding(str(tmp_path / "gone.py"), 3)])
    assert len(kept) == 1 and n == 0


def test_case_insensitive_rule_match(tmp_path):
    path = _write(tmp_path, "eval(x)  # xsec: ignore[py-eval]\n")
    kept, n = filter_suppressed([_finding(path, 1)])
    assert kept == [] and n == 1
