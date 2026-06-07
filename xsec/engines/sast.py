"""Static analysis for Python: parse once, run the rules."""

from __future__ import annotations

import ast
from pathlib import Path

from xsec.engines.base import Engine
from xsec.models import Finding, Severity
from xsec.parallel import parallel_map
from xsec.rules import python as pyrules
from xsec.safety import read_text_safely


def scan_python_file(path: Path) -> list[Finding]:
    """Scan one Python file. Module-level so a process pool can pickle it."""
    source = read_text_safely(path)
    if source is None:  # too large, binary, or unreadable - skip quietly
        return []

    findings: list[Finding] = list(_regex_scan(path, source))

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        # can't parse it, but regex hits above are still worth keeping
        findings.append(Finding(
            rule_id="PY-SYNTAX", severity=Severity.INFO,
            message=f"Could not parse (syntax error): {exc.msg}",
            file=str(path), line=exc.lineno or 0, engine="sast",
        ))
        return findings

    lines = source.splitlines()
    for node in ast.walk(tree):
        for rule in pyrules.AST_RULES:
            for finding in rule(node):
                finding.file = str(path)
                if finding.line and finding.line <= len(lines):
                    finding.snippet = lines[finding.line - 1].strip()
                findings.append(finding)
    return findings


def _regex_scan(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        for rule in pyrules.REGEX_RULES:
            if rule.pattern.search(line):
                findings.append(Finding(
                    rule_id=rule.rule_id, severity=rule.severity,
                    message=rule.message, file=str(path), line=lineno,
                    engine="sast", fix=rule.fix, snippet=line.strip(),
                ))
    return findings


class SastEngine(Engine):
    name = "sast"

    def analyze(self, files: list[Path]) -> list[Finding]:
        py_files = [p for p in files if p.suffix == ".py"]
        return parallel_map(scan_python_file, py_files)
