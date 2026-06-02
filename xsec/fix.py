"""Auto-fix engine: rewrite a few unsafe patterns safely.

Edits are made on the AST so we touch the exact call, computed as byte
offsets and applied back-to-front. Every patched file is re-parsed before
it's written, so we never leave broken code behind.

SAFE fixes keep the same behavior (yaml.load -> yaml.safe_load) and run with
--fix. RISKY fixes can change behavior (md5 -> sha256) and only run with
--unsafe-fixes.
"""

from __future__ import annotations

import ast
import enum
from dataclasses import dataclass
from pathlib import Path


class Confidence(enum.Enum):
    SAFE = "safe"
    RISKY = "risky"


@dataclass
class Edit:
    start: int          # byte offset, inclusive
    end: int            # byte offset, exclusive
    replacement: str
    rule_id: str
    confidence: Confidence
    description: str


@dataclass
class FileFix:
    path: Path
    applied: list[Edit]
    skipped_risky: list[Edit]


def _line_starts(data: bytes) -> list[int]:
    # byte offset where each line begins (line 1 at index 0)
    starts = [0]
    for i, b in enumerate(data):
        if b == 0x0A:
            starts.append(i + 1)
    return starts


def _offset(starts: list[int], lineno: int, col: int) -> int:
    return starts[lineno - 1] + col


def _seg(data: bytes, starts: list[int], node: ast.AST) -> str:
    s = _offset(starts, node.lineno, node.col_offset)
    e = _offset(starts, node.end_lineno, node.end_col_offset)
    return data[s:e].decode("utf-8")


def _call_attr(node: ast.Call) -> tuple[str, ast.Attribute | None]:
    # (last attr name, attr node) for calls like a.b.c()
    if isinstance(node.func, ast.Attribute):
        return node.func.attr, node.func
    return "", None


def _dotted(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        parts = [f.attr]
        cur = f.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _kw(node: ast.Call, name: str) -> ast.keyword | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw
    return None


def _is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _plan_edits(data: bytes, tree: ast.AST) -> list[Edit]:
    starts = _line_starts(data)
    edits: list[Edit] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted(node)
        last_attr, attr_node = _call_attr(node)

        # SAFE: yaml.load(...) -> yaml.safe_load(...) when no Loader given
        if last_attr == "load" and dotted.endswith("yaml.load") \
                and _kw(node, "Loader") is None and attr_node is not None:
            value_text = _seg(data, starts, attr_node.value)
            edits.append(Edit(
                _offset(starts, attr_node.value.lineno, attr_node.value.col_offset),
                _offset(starts, node.func.end_lineno, node.func.end_col_offset),
                f"{value_text}.safe_load", "PY-YAML-LOAD", Confidence.SAFE,
                "yaml.load -> yaml.safe_load",
            ))

        # RISKY: weak hash -> sha256 (the digest changes)
        if last_attr in {"md5", "sha1"} and dotted.startswith("hashlib.") \
                and attr_node is not None:
            value_text = _seg(data, starts, attr_node.value)
            edits.append(Edit(
                _offset(starts, attr_node.value.lineno, attr_node.value.col_offset),
                _offset(starts, node.func.end_lineno, node.func.end_col_offset),
                f"{value_text}.sha256", "PY-WEAK-HASH", Confidence.RISKY,
                f"hashlib.{last_attr} -> hashlib.sha256",
            ))

        # RISKY: debug=True -> debug=False
        if last_attr == "run":
            kw = _kw(node, "debug")
            if kw is not None and _is_true(kw.value):
                edits.append(Edit(
                    _offset(starts, kw.value.lineno, kw.value.col_offset),
                    _offset(starts, kw.value.end_lineno, kw.value.end_col_offset),
                    "False", "PY-FLASK-DEBUG", Confidence.RISKY,
                    "debug=True -> debug=False",
                ))

    return edits


def fix_file(path: Path, include_risky: bool = False) -> FileFix | None:
    """Fix one file. Returns None if nothing changed."""
    try:
        data = path.read_bytes()
        tree = ast.parse(data.decode("utf-8", errors="replace"), filename=str(path))
    except (OSError, SyntaxError):
        return None

    edits = _plan_edits(data, tree)
    if not edits:
        return None

    to_apply = [e for e in edits if e.confidence is Confidence.SAFE or include_risky]
    skipped = [e for e in edits if e.confidence is Confidence.RISKY and not include_risky]

    if not to_apply:
        return FileFix(path, [], skipped)

    # apply back-to-front so earlier offsets stay valid
    new = data
    for e in sorted(to_apply, key=lambda x: x.start, reverse=True):
        new = new[:e.start] + e.replacement.encode("utf-8") + new[e.end:]

    # don't write something that no longer parses
    try:
        ast.parse(new.decode("utf-8"))
    except SyntaxError:
        return FileFix(path, [], skipped)

    path.write_bytes(new)
    return FileFix(path, to_apply, skipped)


def fix_files(files: list[Path], include_risky: bool = False) -> list[FileFix]:
    out: list[FileFix] = []
    for f in files:
        if f.suffix != ".py":
            continue
        result = fix_file(f, include_risky=include_risky)
        if result is not None and (result.applied or result.skipped_risky):
            out.append(result)
    return out
