"""Shared data types: findings and scan results."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Severity levels, low to high (so they sort)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass
class Finding:
    """One issue found in a file."""

    rule_id: str
    severity: Severity
    message: str
    file: str
    line: int = 0
    column: int = 0
    engine: str = "sast"  # sast / ai / deps
    fix: str | None = None
    snippet: str | None = None

    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file


@dataclass
class ScanResult:
    """Everything one scan produced."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    def add(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def sorted(self) -> list[Finding]:
        # worst first, then by file and line
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.file, f.line),
        )

    def counts(self) -> dict[Severity, int]:
        out: dict[Severity, int] = {s: 0 for s in Severity}
        for f in self.findings:
            out[f.severity] += 1
        return out
