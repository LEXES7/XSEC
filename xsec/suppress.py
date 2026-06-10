"""Inline finding suppression via ``xsec: ignore`` comments.

A finding is suppressed when its line (or the comment-only line directly
above it) carries a marker:

    risky_call(x)                  # xsec: ignore
    risky_call(x)                  # xsec: ignore[PY-EVAL]
    // xsec: ignore[JS-EVAL, JS-INNERHTML]      (JS/TS/Java style)

A bare ``ignore`` silences every rule on that line; ``ignore[RULE, ...]``
silences only the listed rule IDs. This is the per-line counterpart to the
config file's rule/path suppressions: precise, visible in review, and
self-documenting at the offending line.
"""

from __future__ import annotations

import re
from pathlib import Path

from xsec.models import Finding
from xsec.safety import read_text_safely

_MARKER = re.compile(
    r"(?:#|//)\s*xsec:\s*ignore(?:\[([A-Za-z0-9_\-*,\s]*)\])?",
)


def _marker_rules(line: str) -> set[str] | None:
    """The rule IDs a line's marker suppresses.

    Returns ``None`` if the line has no marker, the empty set for a bare
    ``xsec: ignore`` (suppress everything), or the set of listed rule IDs.
    """
    m = _MARKER.search(line)
    if m is None:
        return None
    if m.group(1) is None:
        return set()
    return {r.strip().upper() for r in m.group(1).split(",") if r.strip()}


def _is_comment_only(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("#") or stripped.startswith("//")


def _line_suppresses(lines: list[str], lineno: int, rule_id: str) -> bool:
    """Does line ``lineno`` (1-based) carry a marker covering ``rule_id``?"""
    # marker on the finding's own line
    for candidate in (lineno, lineno - 1):
        if not 1 <= candidate <= len(lines):
            continue
        line = lines[candidate - 1]
        # the line above only counts if it's a standalone comment
        if candidate != lineno and not _is_comment_only(line):
            continue
        rules = _marker_rules(line)
        if rules is not None and (not rules or rule_id.upper() in rules):
            return True
    return False


def filter_suppressed(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Drop findings whose line carries an ``xsec: ignore`` marker.

    Returns (kept findings, number suppressed). Findings without a line
    number (file-level, e.g. dependency findings) are never suppressed here.
    """
    cache: dict[str, list[str] | None] = {}
    kept: list[Finding] = []
    suppressed = 0

    for f in findings:
        if not f.line:
            kept.append(f)
            continue
        if f.file not in cache:
            text = read_text_safely(Path(f.file))
            cache[f.file] = text.splitlines() if text is not None else None
        lines = cache[f.file]
        if lines is not None and _line_suppresses(lines, f.line, f.rule_id):
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed
