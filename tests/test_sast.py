"""SAST engine tests: bad code flags, clean code doesn't."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from xsec.engines.sast import SastEngine


def _scan(tmp_path: Path, code: str) -> set[str]:
    f = tmp_path / "sample.py"
    f.write_text(textwrap.dedent(code))
    findings = SastEngine().analyze([f])
    return {x.rule_id for x in findings}


@pytest.mark.parametrize(
    "code, expected_rule",
    [
        ("eval(user_input)", "PY-EVAL"),
        ("exec(payload)", "PY-EVAL"),
        ("import os\nos.system(cmd)", "PY-OS-SYSTEM"),
        ("import subprocess\nsubprocess.run(cmd, shell=True)", "PY-SUBPROCESS-SHELL"),
        ("import pickle\npickle.loads(data)", "PY-PICKLE"),
        ("import yaml\nyaml.load(data)", "PY-YAML-LOAD"),
        ("import requests\nrequests.get(url, verify=False)", "PY-TLS-VERIFY"),
        ("import hashlib\nhashlib.md5(b'x')", "PY-WEAK-HASH"),
        ("app.run(debug=True)", "PY-FLASK-DEBUG"),
        ('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', "PY-SECRET-AWS"),
        ('password = "hunter2horse"', "PY-SECRET-GENERIC"),
    ],
)
def test_detects(tmp_path, code, expected_rule):
    assert expected_rule in _scan(tmp_path, code)


def test_clean_code_has_no_findings(tmp_path):
    code = """
        import subprocess

        def safe(cmd_args):
            return subprocess.run(cmd_args, shell=False, check=True)
    """
    assert _scan(tmp_path, code) == set()


def test_yaml_safe_load_is_ok(tmp_path):
    assert "PY-YAML-LOAD" not in _scan(tmp_path, "import yaml\nyaml.safe_load(d)")


def test_syntax_error_is_reported_not_raised(tmp_path):
    assert "PY-SYNTAX" in _scan(tmp_path, "def broken(:\n    pass")
