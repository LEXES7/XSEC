"""Java regex engine tests: bad code flags, clean code doesn't."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from xsec.engines.regex_engine import RegexEngine


def _scan(tmp_path: Path, code: str, name: str = "Sample.java") -> set[str]:
    f = tmp_path / name
    f.write_text(textwrap.dedent(code))
    return {x.rule_id for x in RegexEngine().analyze([f])}


@pytest.mark.parametrize(
    "code, expected_rule",
    [
        ('Runtime.getRuntime().exec("ping " + host);', "JAVA-RUNTIME-EXEC"),
        ('st.executeQuery("SELECT * FROM t WHERE x = \'" + v + "\'");', "JAVA-SQL-CONCAT"),
        ("ObjectInputStream o = new ObjectInputStream(raw);", "JAVA-DESERIALIZE"),
        ('MessageDigest.getInstance("MD5");', "JAVA-WEAK-HASH"),
        ('Cipher.getInstance("DES");', "JAVA-WEAK-CIPHER"),
        ("Random r = new Random();", "JAVA-INSECURE-RANDOM"),
        ("var f = DocumentBuilderFactory.newInstance();", "JAVA-XXE"),
        ('String k = "AKIAIOSFODNN7EXAMPLE";', "JAVA-SECRET-AWS"),
        ('String password = "hunter2horse";', "JAVA-SECRET-GENERIC"),
    ],
)
def test_detects(tmp_path, code, expected_rule):
    assert expected_rule in _scan(tmp_path, code)


def test_clean_java_has_no_findings(tmp_path):
    code = """
        public class Clean {
            int add(int a, int b) {
                return a + b;
            }
        }
    """
    assert _scan(tmp_path, code) == set()


def test_prepared_statement_is_not_flagged(tmp_path):
    # a parameterized query has no concatenation, so no SQLi finding
    code = 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE x = ?");'
    assert "JAVA-SQL-CONCAT" not in _scan(tmp_path, code)


def test_commented_line_is_ignored(tmp_path):
    assert "JAVA-RUNTIME-EXEC" not in _scan(
        tmp_path, '// Runtime.getRuntime().exec("x");'
    )
