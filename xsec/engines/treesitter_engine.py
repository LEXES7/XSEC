"""Syntax-aware JS/TS/Java scanning via tree-sitter (optional).

The plain regex engine can't tell code from comments or string literals, so
``/* eval(x) */`` and ``const s = "eval(x)"`` produce false positives. This
engine parses the file with tree-sitter and runs the *same* rule sets, but a
match only counts when it starts in real code:

* matches inside comments are dropped for every rule except secrets — a real
  credential pasted into a comment is still a leak;
* matches inside string literals are dropped for non-secret rules — secrets
  are string literals, so secret rules keep firing there.

It is a drop-in replacement for the regex engine and is used automatically
when the optional tree-sitter packages are installed
(``pip install 'xsec[treesitter]'``); otherwise the CLI falls back to regex.
"""

from __future__ import annotations

import bisect
from pathlib import Path

from xsec.engines.base import Engine
from xsec.models import Finding
from xsec.rules import java as javarules
from xsec.rules import javascript as jsrules
from xsec.safety import read_text_safely

_LANG_FOR_SUFFIX = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
    ".java": "java",
}

_RULES_FOR_SUFFIX = {
    suffix: (javarules.RULES if suffix == ".java" else jsrules.RULES)
    for suffix in _LANG_FOR_SUFFIX
}

_COMMENT_TYPES = {"comment", "line_comment", "block_comment"}
# string_fragment (not the whole template_string) so code inside `${...}`
# interpolations still counts as code
_STRING_TYPES = {"string_fragment", "string_literal", "character_literal", "text_block"}


def _is_secret_rule(rule_id: str) -> bool:
    return "-SECRET-" in rule_id


class _Ranges:
    """Sorted, non-overlapping byte ranges with a fast membership test."""

    def __init__(self, spans: list[tuple[int, int]]) -> None:
        spans.sort()
        self.starts = [s for s, _ in spans]
        self.ends = [e for _, e in spans]

    def __contains__(self, offset: int) -> bool:
        i = bisect.bisect_right(self.starts, offset) - 1
        return i >= 0 and offset < self.ends[i]


def _collect_spans(root) -> tuple[_Ranges, _Ranges]:
    """Walk the tree once, collecting comment and string-content spans."""
    comments: list[tuple[int, int]] = []
    strings: list[tuple[int, int]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in _COMMENT_TYPES:
            comments.append((node.start_byte, node.end_byte))
            continue
        if node.type in _STRING_TYPES:
            strings.append((node.start_byte, node.end_byte))
            continue
        stack.extend(node.children)
    return _Ranges(comments), _Ranges(strings)


class TreeSitterEngine(Engine):
    name = "syntax"

    def __init__(self) -> None:
        self._parsers: dict[str, object] = {}

    def available(self) -> tuple[bool, str]:
        try:
            import tree_sitter  # noqa: F401
            import tree_sitter_java  # noqa: F401
            import tree_sitter_javascript  # noqa: F401
            import tree_sitter_typescript  # noqa: F401
        except ImportError:
            return False, "tree-sitter not installed (pip install 'xsec[treesitter]')"
        return True, ""

    def _parser(self, lang_name: str):
        if lang_name not in self._parsers:
            import tree_sitter_java
            import tree_sitter_javascript
            import tree_sitter_typescript
            from tree_sitter import Language, Parser

            raw = {
                "javascript": tree_sitter_javascript.language,
                "typescript": tree_sitter_typescript.language_typescript,
                "tsx": tree_sitter_typescript.language_tsx,
                "java": tree_sitter_java.language,
            }[lang_name]()
            self._parsers[lang_name] = Parser(Language(raw))
        return self._parsers[lang_name]

    def analyze(self, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            if path.suffix in _LANG_FOR_SUFFIX:
                findings.extend(self._scan_file(path))
        return findings

    def _scan_file(self, path: Path) -> list[Finding]:
        source = read_text_safely(path)
        if source is None:
            return []
        rules = _RULES_FOR_SUFFIX[path.suffix]
        data = source.encode("utf-8")
        tree = self._parser(_LANG_FOR_SUFFIX[path.suffix]).parse(data)
        comments, strings = _collect_spans(tree.root_node)

        out: list[Finding] = []
        line_start = 0  # byte offset where the current line begins
        for lineno, line in enumerate(source.splitlines(keepends=True), start=1):
            stripped = line.rstrip("\r\n")
            for rule in rules:
                m = rule.pattern.search(stripped)
                if m is None:
                    continue
                offset = line_start + len(stripped[: m.start()].encode("utf-8"))
                if offset in comments and not _is_secret_rule(rule.rule_id):
                    continue
                if offset in strings and not _is_secret_rule(rule.rule_id):
                    continue
                out.append(Finding(
                    rule_id=rule.rule_id, severity=rule.severity,
                    message=rule.message, file=str(path), line=lineno,
                    engine="regex", fix=rule.fix, snippet=stripped.strip(),
                ))
            line_start += len(line.encode("utf-8"))
        return out

    @staticmethod
    def supported_suffixes() -> set[str]:
        return set(_LANG_FOR_SUFFIX)
