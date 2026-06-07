"""Tests for file discovery: which files get picked up, which get skipped."""

from __future__ import annotations

from pathlib import Path

from xsec.discovery import discover


def _names(paths: list[Path]) -> set[str]:
    return {p.name for p in paths}


def test_finds_supported_sources(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.js").write_text("var x = 1;\n")
    (tmp_path / "c.txt").write_text("not code\n")
    found = _names(discover(tmp_path))
    assert "a.py" in found and "b.js" in found
    assert "c.txt" not in found  # unknown extension


def test_skips_build_and_dependency_dirs(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    for d in ["node_modules", "dist", "out", "target", ".venv", "__pycache__"]:
        sub = tmp_path / d
        sub.mkdir()
        (sub / "junk.py").write_text("eval(x)\n")
    found = _names(discover(tmp_path))
    assert found == {"app.py"}  # only the real source, none of the build dirs


def test_skips_minified_and_sourcemaps(tmp_path):
    (tmp_path / "app.js").write_text("var x = 1;\n")
    (tmp_path / "app.min.js").write_text("var x=1;\n")
    (tmp_path / "bundle.js.map").write_text("{}\n")
    (tmp_path / "vendor.bundle.js").write_text("var y=1;\n")
    found = _names(discover(tmp_path))
    assert found == {"app.js"}


def test_manifest_matched_by_name_even_if_generated_pattern(tmp_path):
    # exact-name matches (e.g. for --deps) win over the generated-file skip
    (tmp_path / "package.json").write_text("{}\n")
    found = _names(discover(tmp_path, suffixes=set(), names={"package.json"}))
    assert "package.json" in found


def test_single_file_target_still_works(tmp_path):
    f = tmp_path / "solo.py"
    f.write_text("x = 1\n")
    assert discover(f) == [f]
