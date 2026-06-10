"""Tree-sitter engine tests (skipped when the optional packages are absent)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_javascript")
pytest.importorskip("tree_sitter_typescript")
pytest.importorskip("tree_sitter_java")

from xsec.engines.treesitter_engine import TreeSitterEngine  # noqa: E402


def _scan(tmp_path: Path, code: str, name: str = "sample.js") -> set[str]:
    f = tmp_path / name
    f.write_text(textwrap.dedent(code))
    return {x.rule_id for x in TreeSitterEngine().analyze([f])}


def test_engine_reports_available():
    ok, _ = TreeSitterEngine().available()
    assert ok


def test_real_eval_is_flagged(tmp_path):
    assert "JS-EVAL" in _scan(tmp_path, "const x = eval(input);")


def test_block_comment_is_not_flagged(tmp_path):
    # the line-regex engine false-positives here; the parse tree knows better
    assert "JS-EVAL" not in _scan(tmp_path, "/* const x = eval(input); */")


def test_line_comment_is_not_flagged(tmp_path):
    assert "JS-EVAL" not in _scan(tmp_path, "// const x = eval(input);")


def test_string_literal_is_not_flagged(tmp_path):
    assert "JS-EVAL" not in _scan(tmp_path, 'const doc = "never call eval(x) here";')


def test_code_inside_template_interpolation_is_flagged(tmp_path):
    assert "JS-EVAL" in _scan(tmp_path, "const s = `value: ${eval(x)}`;")


def test_secret_in_string_still_flagged(tmp_path):
    assert "JS-SECRET-AWS" in _scan(tmp_path, 'const k = "AKIAIOSFODNN7EXAMPLE";')


def test_secret_in_comment_still_flagged(tmp_path):
    # a leaked credential is a leak even in a comment
    assert "JS-SECRET-AWS" in _scan(tmp_path, "// old key: AKIAIOSFODNN7EXAMPLE")


def test_typescript_and_tsx(tmp_path):
    assert "JS-EVAL" in _scan(tmp_path, "const x = eval(s);", name="sample.ts")
    assert "JS-EVAL" not in _scan(tmp_path, "/* eval(s) */", name="sample.tsx")


def test_java_block_comment_not_flagged(tmp_path):
    code = """
        class A {
            /* Runtime.getRuntime().exec(cmd); */
            void run() {}
        }
    """
    assert "JAVA-RUNTIME-EXEC" not in _scan(tmp_path, code, name="A.java")


def test_java_real_exec_flagged(tmp_path):
    code = """
        class A {
            void run(String cmd) throws Exception {
                Runtime.getRuntime().exec(cmd);
            }
        }
    """
    assert "JAVA-RUNTIME-EXEC" in _scan(tmp_path, code, name="A.java")


def test_finding_lines_match(tmp_path):
    f = tmp_path / "sample.js"
    f.write_text("const a = 1;\nconst x = eval(s);\n")
    findings = TreeSitterEngine().analyze([f])
    evals = [x for x in findings if x.rule_id == "JS-EVAL"]
    assert evals and evals[0].line == 2
