"""JS/TS regex engine tests: bad code flags, clean code doesn't."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from xsec.engines.regex_engine import RegexEngine


def _scan(tmp_path: Path, code: str, name: str = "sample.js") -> set[str]:
    f = tmp_path / name
    f.write_text(textwrap.dedent(code))
    return {x.rule_id for x in RegexEngine().analyze([f])}


@pytest.mark.parametrize(
    "code, expected_rule",
    [
        ("const x = eval(input);", "JS-EVAL"),
        ("const f = new Function('a', 'return a');", "JS-FUNCTION-CTOR"),
        ("cp.exec(`ls ${dir}`);", "JS-CHILD-PROCESS-EXEC"),
        ("el.innerHTML = userInput;", "JS-INNERHTML"),
        ("document.write(stuff);", "JS-DOCUMENT-WRITE"),
        ('crypto.createHash("md5");', "JS-WEAK-HASH"),
        ("const a = { rejectUnauthorized: false };", "JS-TLS-REJECT"),
        ('const k = "AKIAIOSFODNN7EXAMPLE";', "JS-SECRET-AWS"),
        ('const password = "hunter2horse";', "JS-SECRET-GENERIC"),
    ],
)
def test_detects(tmp_path, code, expected_rule):
    assert expected_rule in _scan(tmp_path, code)


def test_typescript_extension_is_scanned(tmp_path):
    assert "JS-EVAL" in _scan(tmp_path, "const x = eval(s);", name="sample.ts")


def test_clean_js_has_no_findings(tmp_path):
    code = """
        function add(a, b) {
          return a + b;
        }
        module.exports = { add };
    """
    assert _scan(tmp_path, code) == set()


def test_commented_line_is_ignored(tmp_path):
    # a commented-out eval shouldn't be reported
    assert "JS-EVAL" not in _scan(tmp_path, "// const x = eval(input);")


def test_python_files_are_left_to_other_engines(tmp_path):
    # the regex engine only handles JS-family extensions
    assert _scan(tmp_path, "eval(x)", name="thing.py") == set()
