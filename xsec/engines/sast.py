"""Static analysis for Python: parse once, run the rules."""

from __future__ import annotations

import ast
from pathlib import Path

from xsec.engines.base import Engine
from xsec.models import Finding, Severity
from xsec.rules import python as pyrules


class SastEngine(Engine):
    name = "sast"

    def analyze(self, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            if path.suffix != ".py":
                continue
            findings.extend(self._scan_file(path))
        return findings

    def _scan_file(self, path: Path) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return [Finding(
                rule_id="XSEC-READ-ERROR", severity=Severity.INFO,
                message=f"Could not read file: {exc}", file=str(path), engine="sast",
            )]

        findings: list[Finding] = []
        findings.extend(self._regex_scan(path, source))

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

    def _regex_scan(self, path: Path, source: str) -> list[Finding]:
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
