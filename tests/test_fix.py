"""Tests for the auto-fix engine."""

from __future__ import annotations

import textwrap
from pathlib import Path

from xsec.engines.sast import SastEngine
from xsec.fix import Confidence, fix_file


def _write(tmp_path: Path, code: str) -> Path:
    f = tmp_path / "sample.py"
    f.write_text(textwrap.dedent(code))
    return f


def test_safe_fix_yaml_load(tmp_path):
    f = _write(tmp_path, "import yaml\nx = yaml.load(data)\n")
    result = fix_file(f)
    assert result is not None and len(result.applied) == 1
    assert "yaml.safe_load(data)" in f.read_text()
    # And the finding is gone after fixing.
    assert "PY-YAML-LOAD" not in {x.rule_id for x in SastEngine().analyze([f])}


def test_risky_fix_skipped_by_default(tmp_path):
    f = _write(tmp_path, "import hashlib\nh = hashlib.md5(b'x')\n")
    result = fix_file(f, include_risky=False)
    assert result is not None
    assert result.applied == []
    assert len(result.skipped_risky) == 1
    assert result.skipped_risky[0].confidence is Confidence.RISKY
    assert "hashlib.md5" in f.read_text()  # unchanged


def test_risky_fix_applied_with_flag(tmp_path):
    f = _write(tmp_path, "import hashlib\nh = hashlib.md5(b'x')\n")
    result = fix_file(f, include_risky=True)
    assert result is not None and len(result.applied) == 1
    assert "hashlib.sha256(b'x')" in f.read_text()


def test_flask_debug_fix(tmp_path):
    f = _write(tmp_path, "app.run(debug=True, port=5000)\n")
    fix_file(f, include_risky=True)
    text = f.read_text()
    assert "debug=False" in text and "port=5000" in text


def test_no_change_returns_none(tmp_path):
    f = _write(tmp_path, "import yaml\nyaml.safe_load(data)\n")
    assert fix_file(f) is None


def test_yaml_with_loader_not_touched(tmp_path):
    f = _write(tmp_path, "import yaml\nyaml.load(d, Loader=yaml.SafeLoader)\n")
    assert fix_file(f) is None
