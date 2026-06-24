from __future__ import annotations

import dataclasses
import json
import os

from rich.console import Console
from rich.table import Table
from rich.text import Text

from xsec.cwe import cwe_tag
from xsec.models import ScanResult, Severity


def _loc(file: str, line: int) -> str:
    # show the path relative to where you're running, so the line number fits
    try:
        rel = os.path.relpath(file)
        if rel.startswith(".."):
            rel = file
    except ValueError:
        rel = file
    return f"{rel}:{line}" if line else rel

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_console(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    if not result.findings:
        console.print(
            f"\n[bold green]✓ No findings[/] across "
            f"{result.files_scanned} file(s).\n"
        )
        _print_errors(result, console)
        return

    table = Table(title="XSEC findings", show_lines=False, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Location", overflow="fold")
    table.add_column("Issue")

    for f in result.sorted():
        sev = Text(str(f.severity), style=_SEV_STYLE.get(f.severity, ""))
        msg = f.message
        if f.fix:
            msg += f"\n[dim]→ {f.fix}[/dim]"
        table.add_row(sev, f.rule_id, _loc(f.file, f.line), Text.from_markup(msg))

    console.print()
    console.print(table)
    _print_summary(result, console)
    _print_errors(result, console)


def _print_summary(result: ScanResult, console: Console) -> None:
    counts = result.counts()
    parts = []
    for sev in sorted(Severity, reverse=True):
        if counts[sev]:
            style = _SEV_STYLE.get(sev, "")
            parts.append(f"[{style}]{counts[sev]} {sev}[/]")
    summary = "  ".join(parts) if parts else "none"
    console.print(
        f"\n[bold]{len(result.findings)} finding(s)[/] in "
        f"{result.files_scanned} file(s):  {summary}\n"
    )


def _print_errors(result: ScanResult, console: Console) -> None:
    for err in result.errors:
        # escape so text like "[ai]" isn't swallowed as Rich markup
        console.print("! " + err, style="yellow", markup=False)


def to_json(result: ScanResult) -> str:
    payload = {
        "files_scanned": result.files_scanned,
        "errors": result.errors,
        "summary": {str(k): v for k, v in result.counts().items() if v},
        "findings": [
            {
                **dataclasses.asdict(f),
                "severity": str(f.severity),
                "cwe": cwe_tag(f.rule_id),
            }
            for f in result.sorted()
        ],
    }
    return json.dumps(payload, indent=2)
