"""Security / robustness tests: XSEC must survive hostile or huge input.

XSEC scans untrusted code, so a malicious repo is part of the threat model.
These tests pin the resource limits and the no-symlink / no-huge-file
guarantees so they can't silently regress.
"""

from __future__ import annotations

import os
import time

import pytest

from xsec.discovery import discover
from xsec.engines.regex_engine import RegexEngine
from xsec.engines.sast import SastEngine
from xsec.rules import java as javarules
from xsec.rules import javascript as jsrules
from xsec.rules import python as pyrules
from xsec.safety import (
    MAX_FILE_BYTES,
    MAX_LINE_CHARS,
    is_probably_binary,
    read_text_safely,
)


def test_oversized_file_is_skipped(tmp_path):
    big = tmp_path / "big.py"
    big.write_bytes(b"# pad\n" + b"x" * (MAX_FILE_BYTES + 1))
    assert read_text_safely(big) is None
    # engine skips it rather than loading it
    assert SastEngine().analyze([big]) == []


def test_binary_file_is_skipped(tmp_path):
    f = tmp_path / "thing.js"
    f.write_bytes(b"var x = 1;\x00\x00 eval(y)")
    assert is_probably_binary(f.read_bytes())
    assert read_text_safely(f) is None
    assert RegexEngine().analyze([f]) == []


def test_long_lines_are_truncated(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("x = '" + "A" * (MAX_LINE_CHARS * 3) + "'\n")
    text = read_text_safely(f)
    assert text is not None
    assert all(len(line) <= MAX_LINE_CHARS for line in text.splitlines())


def test_symlinks_are_not_followed(tmp_path):
    # a symlink pointing outside the tree must not be scanned
    outside = tmp_path / "secret.py"
    outside.write_text("eval(x)\n")
    scan_dir = tmp_path / "repo"
    scan_dir.mkdir()
    link = scan_dir / "link.py"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported here")
    found = discover(scan_dir)
    assert link not in found
    assert all(p.name != "link.py" for p in found)


def test_redos_resistance():
    # every regex rule must handle a worst-case line fast
    rules = list(pyrules.REGEX_RULES) + list(jsrules.RULES) + list(javarules.RULES)
    payloads = [
        "A" * MAX_LINE_CHARS,
        "password='" + "a" * 4000,
        "x" * 2500 + "==" + "y" * 2500,
        'st.executeQuery("' + "a+" * 2000,
    ]
    for rule in rules:
        for p in payloads:
            start = time.perf_counter()
            rule.pattern.search(p)
            assert (time.perf_counter() - start) < 0.5  # generous CI margin


def test_nul_bytes_dont_crash_python_engine(tmp_path):
    f = tmp_path / "weird.py"
    f.write_bytes(b"x = 1\x00\n")
    # binary -> skipped, no exception
    assert SastEngine().analyze([f]) == []
