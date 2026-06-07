"""Walk a path and collect the files we can scan."""

from __future__ import annotations

import os
from pathlib import Path

from xsec.safety import MAX_FILES

_SKIP_DIRS = {
    # VCS / caches
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".cache",
    # python envs / packaging
    ".venv", "venv", "env", ".tox", "build", "dist", "site-packages",
    "*.egg-info",
    # node / js build output
    "node_modules", "out", "coverage", ".next", ".nuxt", ".svelte-kit",
    # other languages' build output
    "target", "bin", "obj", ".gradle", "vendor",
    # editors
    ".idea", ".vscode",
}

# Generated/compiled files that look like source but aren't worth scanning
# (minified bundles, source maps). Skipped so we don't waste AI tokens or
# produce noisy regex hits on machine-generated code.
_SKIP_FILE_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".map")

# languages with native (non-AI) rules: Python AST + JS/TS/Java regex
_SCAN_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java"}


def _is_generated(name: str) -> bool:
    return any(name.endswith(suf) for suf in _SKIP_FILE_SUFFIXES)


def discover(
    root: Path,
    suffixes: set[str] | None = None,
    names: set[str] | None = None,
) -> list[Path]:
    """Collect files to scan.

    ``suffixes`` matches by extension (e.g. ".py"); ``names`` matches by exact
    filename (e.g. "requirements.txt") for dependency manifests.
    """
    suffixes = suffixes or _SCAN_SUFFIXES
    names = names or set()
    root = root.resolve()

    if root.is_file():
        if root.suffix in suffixes or root.name in names:
            return [root]
        return []

    # os.walk with followlinks=False (the default) so a symlink in a hostile
    # repo can't redirect the scan outside the tree or create a cycle.
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # prune skip-dirs in place so we never descend into them
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            # skip symlinked files explicitly (os.walk lists them as files)
            if path.is_symlink():
                continue
            # skip generated/minified files (unless matched by exact name)
            if name not in names and _is_generated(name):
                continue
            if path.suffix in suffixes or path.name in names:
                found.append(path)
                if len(found) >= MAX_FILES:
                    return sorted(found)
    return sorted(found)
