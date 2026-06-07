"""A generic line-by-line regex engine for languages we don't AST-parse.

It maps file extensions to a rule set and runs every rule against every
(non-comment) line. New languages plug in by adding to ``_RULESETS``.
"""

from __future__ import annotations

from pathlib import Path

from xsec.engines.base import Engine
from xsec.models import Finding
from xsec.parallel import parallel_map
from xsec.rules import java as javarules
from xsec.rules import javascript as jsrules
from xsec.safety import read_text_safely

# extension -> rule list. Several extensions can share one rule set.
_RULESETS = {
    ".js": jsrules.RULES,
    ".jsx": jsrules.RULES,
    ".ts": jsrules.RULES,
    ".tsx": jsrules.RULES,
    ".mjs": jsrules.RULES,
    ".cjs": jsrules.RULES,
    ".java": javarules.RULES,
}

# these languages all use // for line comments, so one marker covers them
_LINE_COMMENT = "//"


def scan_regex_file(path: Path) -> list[Finding]:
    """Scan one JS/TS/Java file. Module-level so a process pool can pickle it."""
    rules = _RULESETS.get(path.suffix)
    if not rules:
        return []
    source = read_text_safely(path)
    if source is None:  # too large, binary, or unreadable
        return []

    out: list[Finding] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        if line.lstrip().startswith(_LINE_COMMENT):
            continue
        for rule in rules:
            if rule.pattern.search(line):
                out.append(Finding(
                    rule_id=rule.rule_id, severity=rule.severity,
                    message=rule.message, file=str(path), line=lineno,
                    engine="regex", fix=rule.fix, snippet=line.strip(),
                ))
    return out


class RegexEngine(Engine):
    name = "regex"

    def analyze(self, files: list[Path]) -> list[Finding]:
        targets = [p for p in files if p.suffix in _RULESETS]
        return parallel_map(scan_regex_file, targets)

    @staticmethod
    def supported_suffixes() -> set[str]:
        return set(_RULESETS)
