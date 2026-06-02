"""Walk a path and collect the files we can scan."""

from __future__ import annotations

from pathlib import Path

_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".venv", "venv", "env", "node_modules", ".tox", "build", "dist",
    ".idea", ".vscode", ".ruff_cache", "site-packages",
}

_SCAN_SUFFIXES = {".py"}


def discover(root: Path, suffixes: set[str] | None = None) -> list[Path]:
    suffixes = suffixes or _SCAN_SUFFIXES
    root = root.resolve()

    if root.is_file():
        return [root] if root.suffix in suffixes else []

    found: list[Path] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in suffixes:
            found.append(path)
    return sorted(found)
