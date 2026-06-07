"""Tests for .xsec.toml config parsing and filtering."""

from __future__ import annotations

from pathlib import Path

from xsec.config import (
    Config,
    apply_config,
    find_config,
    load_config,
    parse_config,
)
from xsec.models import Finding, Severity


def _f(rule: str, file: str) -> Finding:
    return Finding(rule, Severity.HIGH, "msg", file, 1)


def test_parse_scan_defaults():
    cfg = parse_config("""
        [scan]
        min_severity = "MEDIUM"
        ai = true
        deps = false
    """)
    assert cfg.min_severity is Severity.MEDIUM
    assert cfg.ai is True
    assert cfg.deps is False


def test_parse_ai_section():
    cfg = parse_config("""
        [ai]
        provider = "groq"
        model = "llama-3.3-70b-versatile"
        base_url = "https://example.com/v1"
    """)
    assert cfg.ai_provider == "groq"
    assert cfg.ai_model == "llama-3.3-70b-versatile"
    assert cfg.ai_base_url == "https://example.com/v1"


def test_parse_ignore_and_suppress():
    cfg = parse_config("""
        [ignore]
        paths = ["examples/", "*.min.js"]
        rules = ["PY-WEAK-HASH"]

        [[suppress]]
        rule = "PY-EVAL"
        path = "scripts/repl.py"
        reason = "intentional"
    """)
    assert "examples/" in cfg.ignore_paths
    assert "PY-WEAK-HASH" in cfg.ignore_rules
    assert len(cfg.suppressions) == 1
    assert cfg.suppressions[0].rule == "PY-EVAL"
    assert cfg.suppressions[0].path == "scripts/repl.py"


def test_ignore_directory_path():
    cfg = Config(ignore_paths=["examples/"])
    assert cfg.is_path_ignored("examples/vulnerable.py")
    assert cfg.is_path_ignored("/abs/examples/x.py")
    assert not cfg.is_path_ignored("src/app.py")


def test_ignore_glob_path():
    cfg = Config(ignore_paths=["*.min.js"])
    assert cfg.is_path_ignored("static/app.min.js")
    assert not cfg.is_path_ignored("static/app.js")


def test_ignore_rule_everywhere():
    cfg = Config(ignore_rules=["PY-WEAK-HASH"])
    assert cfg.is_suppressed(_f("PY-WEAK-HASH", "a.py"))
    assert not cfg.is_suppressed(_f("PY-EVAL", "a.py"))


def test_suppress_rule_in_one_path_only():
    cfg = parse_config("""
        [[suppress]]
        rule = "PY-EVAL"
        path = "scripts/repl.py"
    """)
    assert cfg.is_suppressed(_f("PY-EVAL", "scripts/repl.py"))
    assert not cfg.is_suppressed(_f("PY-EVAL", "app.py"))  # different file


def test_apply_config_filters():
    cfg = Config(ignore_paths=["examples/"], ignore_rules=["PY-WEAK-HASH"])
    findings = [
        _f("PY-EVAL", "src/app.py"),         # kept
        _f("PY-EVAL", "examples/bad.py"),    # dropped: path
        _f("PY-WEAK-HASH", "src/h.py"),      # dropped: rule
    ]
    kept = apply_config(findings, cfg)
    assert len(kept) == 1
    assert kept[0].file == "src/app.py"


def test_bad_toml_is_empty_config(tmp_path):
    p = tmp_path / ".xsec.toml"
    p.write_text("this is not = valid toml [[[")
    assert load_config(p) == Config()


def test_find_config_walks_up(tmp_path):
    (tmp_path / ".xsec.toml").write_text("[scan]\nai = true\n")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_config(nested) == tmp_path / ".xsec.toml"


def test_no_config_returns_empty(tmp_path):
    assert find_config(tmp_path) is None
    assert load_config(tmp_path) == Config()
