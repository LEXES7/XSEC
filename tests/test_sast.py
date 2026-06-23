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


@pytest.mark.parametrize(
    "code, expected_rule",
    [
        ('cur.execute(f"SELECT * FROM users WHERE id = {uid}")', "PY-SQL-INJECTION"),
        ('cur.execute("SELECT * FROM t WHERE x = %s" % x)', "PY-SQL-INJECTION"),
        ('cur.execute("SELECT * FROM t WHERE id = {}".format(uid))', "PY-SQL-INJECTION"),
        ('cur.execute("SELECT * FROM t WHERE id = " + uid)', "PY-SQL-INJECTION"),
        ('import jwt\njwt.decode(t, verify=False)', "PY-JWT-NOVERIFY"),
        ('import jwt\njwt.decode(t, options={"verify_signature": False})', "PY-JWT-NOVERIFY"),
        ("import ssl\nctx = ssl._create_unverified_context()", "PY-SSL-NO-VERIFY"),
        ("import ssl, urllib3\nurllib3.PoolManager(cert_reqs=ssl.CERT_NONE)", "PY-SSL-NO-VERIFY"),
        ('tar.extractall("/tmp/out")', "PY-EXTRACTALL"),
        ("import tempfile\np = tempfile.mktemp()", "PY-MKTEMP"),
        ("mark_safe(html)", "PY-MARK-SAFE"),
        ("from xml.dom import minidom\nminidom.parseString(data)", "PY-XXE"),
        ("import random\ntoken = random.getrandbits(64)", "PY-INSECURE-RANDOM"),
        ('app.run(host="0.0.0.0")', "PY-BIND-ALL"),
        ('sock.bind(("0.0.0.0", 8080))', "PY-BIND-ALL"),
        ('import hashlib\nhashlib.new("md5")', "PY-WEAK-HASH"),
        ('GH = "ghp_' + "a1B2" * 9 + '"', "PY-SECRET-GITHUB"),
        # fake secrets are assembled from fragments so the literal never appears
        # in source — otherwise GitHub secret scanning flags our own test data.
        ('STRIPE = "sk' + '_live_' + "aB3dE" * 5 + '"', "PY-SECRET-STRIPE"),
        ('SLACK = "xo' + 'xb-' + "123456789012-abcdefABCDEF" + '"', "PY-SECRET-SLACK"),
        ('G = "AIzaSy' + "a1B2" * 8 + 'x"', "PY-SECRET-GOOGLE"),
    ],
)
def test_detects_new_rules(tmp_path, code, expected_rule):
    assert expected_rule in _scan(tmp_path, code)


@pytest.mark.parametrize(
    "code, absent_rule",
    [
        # parameterized query: the safe pattern we recommend
        ('cur.execute("SELECT * FROM t WHERE id = ?", (uid,))', "PY-SQL-INJECTION"),
        # dynamic string that isn't SQL
        ('cur.execute(f"PRAGMA table_info({name})")', "PY-SQL-INJECTION"),
        # explicit "not used for security" declaration
        ("import hashlib\nhashlib.md5(data, usedforsecurity=False)", "PY-WEAK-HASH"),
        # extraction with the safe members filter
        ('tar.extractall(path, filter="data")', "PY-EXTRACTALL"),
        # signature actually verified
        ('import jwt\njwt.decode(t, key, algorithms=["HS256"])', "PY-JWT-NOVERIFY"),
        # placeholder values are not real secrets
        ('password = "${DB_PASSWORD}"', "PY-SECRET-GENERIC"),
        ('password = "<your-password-here>"', "PY-SECRET-GENERIC"),
        # binding localhost is fine
        ('app.run(host="127.0.0.1")', "PY-BIND-ALL"),
    ],
)
def test_safe_variants_not_flagged(tmp_path, code, absent_rule):
    assert absent_rule not in _scan(tmp_path, code)


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
