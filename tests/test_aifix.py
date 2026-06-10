"""AI auto-fix tests: every gate that protects the user's code, no network."""

from __future__ import annotations

from pathlib import Path

from xsec.aifix import fix_findings_with_ai, static_rule_ids, validate_fix
from xsec.models import Finding, Severity

VULN = "import yaml\n\ndef load(d):\n    return yaml.load(d)\n"
FIXED = "import yaml\n\ndef load(d):\n    return yaml.safe_load(d)\n"


def _finding(path: Path, line: int = 4, rule_id: str = "PY-YAML-LOAD") -> Finding:
    return Finding(
        rule_id=rule_id, severity=Severity.HIGH, message="yaml.load unsafe",
        file=str(path), line=line, fix="Use yaml.safe_load.",
    )


def _vuln_file(tmp_path: Path) -> Path:
    f = tmp_path / "app.py"
    f.write_text(VULN)
    return f


def test_static_rule_ids_python(tmp_path):
    ids = static_rule_ids("app.py", VULN)
    assert ids["PY-YAML-LOAD"] == 1
    assert static_rule_ids("app.py", FIXED)["PY-YAML-LOAD"] == 0


def test_static_rule_ids_javascript():
    assert static_rule_ids("app.js", "el.innerHTML = x;\n")["JS-INNERHTML"] == 1


def test_validate_accepts_a_real_fix(tmp_path):
    f = _vuln_file(tmp_path)
    ok, reason, removed = validate_fix(f, VULN, FIXED)
    assert ok, reason
    assert removed == 1


def test_validate_rejects_no_change(tmp_path):
    ok, reason, _ = validate_fix(_vuln_file(tmp_path), VULN, VULN)
    assert not ok and "no change" in reason


def test_validate_rejects_broken_python(tmp_path):
    ok, reason, _ = validate_fix(_vuln_file(tmp_path), VULN, "def broken(:\n")
    assert not ok


def test_validate_rejects_new_findings(tmp_path):
    sneaky = FIXED + "\neval(input())\n"
    ok, reason, _ = validate_fix(_vuln_file(tmp_path), VULN, sneaky)
    assert not ok and "PY-EVAL" in reason


def test_validate_rejects_cosmetic_rewrite(tmp_path):
    cosmetic = VULN.replace("def load", "def load_data")
    ok, reason, _ = validate_fix(_vuln_file(tmp_path), VULN, cosmetic)
    assert not ok and "remove" in reason


def test_validate_rejects_truncated_response(tmp_path):
    ok, reason, _ = validate_fix(_vuln_file(tmp_path), VULN * 20, "x = 1\n")
    assert not ok and "size" in reason


def test_fix_applies_and_writes(tmp_path):
    f = _vuln_file(tmp_path)

    def fake_request(provider, model, base_url, user):
        assert "PY-YAML-LOAD" in user and "yaml.load" in user
        return FIXED

    outcomes = fix_findings_with_ai([_finding(f)], request=fake_request)
    assert len(outcomes) == 1
    o = outcomes[0]
    assert o.applied and o.fixed_count == 1
    assert "safe_load" in o.diff
    assert f.read_text() == FIXED


def test_rejected_fix_leaves_file_untouched(tmp_path):
    f = _vuln_file(tmp_path)
    outcomes = fix_findings_with_ai(
        [_finding(f)], request=lambda *a: "def broken(:\n",
    )
    assert not outcomes[0].applied
    assert f.read_text() == VULN


def test_provider_error_is_an_outcome_not_a_crash(tmp_path):
    f = _vuln_file(tmp_path)

    def boom(*a):
        raise RuntimeError("rate limited")

    outcomes = fix_findings_with_ai([_finding(f)], request=boom)
    assert not outcomes[0].applied
    assert "rate limited" in outcomes[0].reason
    assert f.read_text() == VULN


def test_file_level_findings_are_skipped(tmp_path):
    dep = Finding(
        rule_id="DEP-VULN", severity=Severity.HIGH, message="m",
        file="requirements.txt", line=0, engine="deps",
    )
    assert fix_findings_with_ai([dep], request=lambda *a: FIXED) == []


def test_oversized_file_is_skipped(tmp_path):
    f = tmp_path / "big.py"
    f.write_text("x = 1\n" * 10_000 + "eval(x)\n")
    outcomes = fix_findings_with_ai(
        [_finding(f, line=10_001, rule_id="PY-EVAL")], request=lambda *a: FIXED,
    )
    assert not outcomes[0].applied and "too large" in outcomes[0].reason
