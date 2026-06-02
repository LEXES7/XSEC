"""The `xsec scan` command.

Exit code is non-zero when a finding meets --fail-on, so it can gate CI.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from xsec import __version__
from xsec.discovery import discover
from xsec.engines.ai_review import AiReviewEngine
from xsec.engines.sast import SastEngine
from xsec.fix import fix_files
from xsec.models import ScanResult, Severity
from xsec.report import console as report
from xsec.report.html import to_html
from xsec.report.sarif import to_sarif

# the AI engine works on any language, so widen discovery when --ai is on
_AI_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb",
    ".php", ".c", ".cpp", ".cs", ".rs",
}

_SEVERITIES = [s.name for s in Severity]


def _parse_severity(value: str) -> Severity:
    try:
        return Severity[value.upper()]
    except KeyError:
        raise argparse.ArgumentTypeError(
            f"severity must be one of {', '.join(_SEVERITIES)}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xsec",
        description="Vulnerability scanner for AI-written code.",
    )
    parser.add_argument("--version", action="version", version=f"xsec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a file or directory.")
    scan.add_argument("path", type=Path, help="File or directory to scan.")
    scan.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")
    scan.add_argument("--sarif", action="store_true", help="Emit SARIF 2.1.0 (GitHub code scanning).")
    scan.add_argument("--html", type=Path, default=None, metavar="FILE",
                      help="Write a self-contained HTML report to FILE.")
    scan.add_argument(
        "--min-severity", type=_parse_severity, default=Severity.INFO,
        metavar="LEVEL", help="Hide findings below this severity.",
    )
    scan.add_argument(
        "--fail-on", type=_parse_severity, default=None, metavar="LEVEL",
        help="Exit non-zero if any finding is at/above this severity.",
    )
    scan.add_argument(
        "--fix", action="store_true",
        help="Apply safe auto-refactors to the code, then re-scan.",
    )
    scan.add_argument(
        "--unsafe-fixes", action="store_true",
        help="With --fix, also apply fixes that may change behavior.",
    )
    scan.add_argument(
        "--ai", action="store_true",
        help="Enable Claude-powered semantic review (needs ANTHROPIC_API_KEY).",
    )
    scan.add_argument(
        "--ai-model", default=None, metavar="MODEL",
        help="Model for --ai (default: claude-opus-4-8).",
    )
    return parser


def run_scan(args: argparse.Namespace) -> int:
    console = Console()
    if not args.path.exists():
        console.print(f"[red]Path not found:[/] {args.path}")
        return 2

    suffixes = _AI_SUFFIXES if args.ai else None
    files = discover(args.path, suffixes=suffixes)
    result = ScanResult(files_scanned=len(files))

    if not files:
        result.errors.append("No scannable source files found.")

    # fix first so the findings we report reflect the fixed code
    if args.fix:
        py_files = [f for f in files if f.suffix == ".py"]
        fixes = fix_files(py_files, include_risky=args.unsafe_fixes)
        _report_fixes(fixes, console, args.unsafe_fixes)

    engines = [SastEngine(), AiReviewEngine(enabled=args.ai, model=args.ai_model)]
    for engine in engines:
        ok, reason = engine.available()
        if not ok:
            result.errors.append(f"Skipped {engine.name} engine: {reason}")
            continue
        result.add(engine.analyze(files))
        result.errors.extend(getattr(engine, "errors", []))

    if args.min_severity > Severity.INFO:
        result.findings = [
            f for f in result.findings if f.severity >= args.min_severity
        ]

    if args.html:
        args.html.write_text(to_html(result), encoding="utf-8")
        console.print(f"[green]HTML report written to[/] {args.html}")

    if args.sarif:
        print(to_sarif(result))
    elif args.json:
        print(report.to_json(result))
    elif not args.html:
        report.render_console(result, console)

    if args.fail_on is not None:
        if any(f.severity >= args.fail_on for f in result.findings):
            return 1
    return 0


def _report_fixes(fixes, console: Console, unsafe: bool) -> None:
    applied = sum(len(f.applied) for f in fixes)
    skipped = sum(len(f.skipped_risky) for f in fixes)

    if applied:
        console.print(f"\n[bold green]Refactored {applied} issue(s):[/]")
        for ff in fixes:
            for e in ff.applied:
                console.print(f"  [green]✓[/] {ff.path}: {e.description}")
    else:
        console.print("\n[dim]No auto-fixable issues found.[/]")

    if skipped and not unsafe:
        console.print(
            f"\n[yellow]{skipped} behavior-changing fix(es) skipped.[/] "
            "Re-run with [bold]--unsafe-fixes[/] to apply them:"
        )
        for ff in fixes:
            for e in ff.skipped_risky:
                console.print(f"  [yellow]·[/] {ff.path}: {e.description}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
