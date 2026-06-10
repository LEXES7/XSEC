"""The `xsec scan` command.

Exit code is non-zero when a finding meets --fail-on, so it can gate CI.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from xsec import __version__
from xsec.aifix import fix_findings_with_ai
from xsec.baseline import BASELINE_NAME, filter_new, load_baseline, save_baseline
from xsec.config import Config, apply_config, load_config
from xsec.discovery import discover
from xsec.engines.ai_review import AiReviewEngine
from xsec.engines.deps import DepsEngine
from xsec.engines.openai_compatible import OpenAICompatibleEngine
from xsec.engines.regex_engine import RegexEngine
from xsec.engines.sast import SastEngine
from xsec.engines.treesitter_engine import TreeSitterEngine
from xsec.fix import fix_files
from xsec.models import ScanResult, Severity
from xsec.report import console as report
from xsec.report.html import to_html
from xsec.report.sarif import to_sarif
from xsec.secrets import clear_api_key, key_status, set_api_key
from xsec.suppress import filter_suppressed

# the AI engine works on any language, so widen discovery when --ai is on
_AI_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb",
    ".php", ".c", ".cpp", ".cs", ".rs",
}

# dependency manifests/lockfiles, matched by exact filename when --deps is on
_MANIFEST_NAMES = {
    "requirements.txt", "package.json",
    "package-lock.json", "poetry.lock", "uv.lock",
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
        "--min-severity", type=_parse_severity, default=None,
        metavar="LEVEL", help="Hide findings below this severity (default INFO, or .xsec.toml).",
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
        "--ai-fix", action="store_true",
        help="Ask the AI provider to rewrite files so the findings are fixed "
             "(rewrites are verified before writing; needs an AI key).",
    )
    scan.add_argument(
        "--ai", action="store_true", default=None,
        help="Enable Claude-powered semantic review (needs ANTHROPIC_API_KEY).",
    )
    scan.add_argument(
        "--deps", action="store_true", default=None,
        help="Check dependencies against the OSV vulnerability database (sends package list to osv.dev).",
    )
    scan.add_argument(
        "--no-config", action="store_true",
        help="Ignore any .xsec.toml config file.",
    )
    scan.add_argument(
        "--baseline", nargs="?", const=BASELINE_NAME, default=None, metavar="FILE",
        help="Hide findings recorded in a baseline file (default: .xsec-baseline.json).",
    )
    scan.add_argument(
        "--ai-model", default=None, metavar="MODEL",
        help="Model for --ai (default depends on provider).",
    )
    scan.add_argument(
        "--ai-provider", default=None,
        choices=["anthropic", "groq", "openrouter", "openai-compatible"],
        help="AI provider for --ai. groq/openrouter have free tiers (default: anthropic).",
    )
    scan.add_argument(
        "--ai-base-url", default=None, metavar="URL",
        help="Base URL for --ai-provider openai-compatible.",
    )
    scan.add_argument(
        "--no-ai-cache", action="store_true",
        help="Re-ask the model even for files whose cached AI results are current.",
    )

    base = sub.add_parser(
        "baseline",
        help="Record current findings to a baseline file so future scans only show new ones.",
    )
    base.add_argument("path", type=Path, help="File or directory to scan.")
    base.add_argument(
        "--output", "-o", type=Path, default=Path(BASELINE_NAME), metavar="FILE",
        help=f"Where to write the baseline (default: {BASELINE_NAME}).",
    )
    base.add_argument("--ai", action="store_true", default=None, help="Include AI findings.")
    base.add_argument("--deps", action="store_true", default=None, help="Include dependency findings.")
    base.add_argument("--no-config", action="store_true", help="Ignore any .xsec.toml.")
    base.add_argument("--ai-model", default=None, metavar="MODEL", help="Model for --ai.")
    base.add_argument(
        "--ai-provider", default=None,
        choices=["anthropic", "groq", "openrouter", "openai-compatible"],
        help="AI provider for --ai (default: anthropic).",
    )
    base.add_argument("--ai-base-url", default=None, metavar="URL", help="Base URL for openai-compatible.")
    base.add_argument("--no-ai-cache", action="store_true", help="Bypass the AI result cache.")

    key = sub.add_parser(
        "key",
        help="Manage AI provider API keys in your OS's encrypted keyring.",
    )
    key.add_argument(
        "action", choices=["set", "clear", "status"],
        help="set: store a key securely · clear: remove it · status: show where the key comes from.",
    )
    key.add_argument(
        "--provider", default="anthropic",
        choices=["anthropic", "groq", "openrouter", "openai-compatible"],
        help="Which provider's key to manage (default: anthropic).",
    )
    return parser


def _make_js_java_engine():
    """Syntax-aware engine when tree-sitter is installed, else line regex."""
    engine = TreeSitterEngine()
    ok, _ = engine.available()
    return engine if ok else RegexEngine()


def _make_ai_engine(
    use_ai: bool, provider: str, model: str | None, base_url: str | None,
    cache: bool = True,
):
    """Pick the right AI engine for the chosen provider."""
    if provider == "anthropic":
        return AiReviewEngine(enabled=use_ai, model=model, cache=cache)
    return OpenAICompatibleEngine(
        provider=provider, model=model, base_url=base_url, enabled=use_ai,
        cache=cache,
    )


def _collect_findings(
    path: Path,
    cfg: Config,
    use_ai: bool,
    use_deps: bool,
    ai_model: str | None,
    *,
    ai_provider: str = "anthropic",
    ai_base_url: str | None = None,
    ai_cache: bool = True,
    fix: bool = False,
    unsafe_fixes: bool = False,
    console: Console | None = None,
) -> ScanResult:
    """Discover files and run every enabled engine. Shared by scan/baseline."""
    suffixes = _AI_SUFFIXES if use_ai else None
    # when deps is on, also pick up dependency manifests by filename
    names = _MANIFEST_NAMES if use_deps else None
    files = discover(path, suffixes=suffixes, names=names)
    # drop files matching ignore.paths before we even scan them
    files = [f for f in files if not cfg.is_path_ignored(str(f))]
    result = ScanResult(files_scanned=len(files))

    if not files:
        result.errors.append("No scannable source files found.")

    # fix first so the findings we report reflect the fixed code
    if fix:
        py_files = [f for f in files if f.suffix == ".py"]
        fixes = fix_files(py_files, include_risky=unsafe_fixes)
        if console is not None:
            _report_fixes(fixes, console, unsafe_fixes)

    engines = [
        SastEngine(),
        _make_js_java_engine(),
        DepsEngine(enabled=use_deps),
        _make_ai_engine(use_ai, ai_provider, ai_model, ai_base_url, cache=ai_cache),
    ]
    for engine in engines:
        ok, reason = engine.available()
        if not ok:
            result.errors.append(f"Skipped {engine.name} engine: {reason}")
            continue
        result.add(engine.analyze(files))
        result.errors.extend(getattr(engine, "errors", []))
    return result


def run_scan(args: argparse.Namespace) -> int:
    console = Console()
    # progress/fix chatter goes to stderr when stdout carries machine output
    info = Console(stderr=True) if (args.json or args.sarif) else console
    if not args.path.exists():
        console.print(f"[red]Path not found:[/] {args.path}")
        return 2

    # config file provides defaults; explicit CLI flags always win
    cfg = Config() if args.no_config else load_config(args.path)
    use_ai = args.ai if args.ai is not None else bool(cfg.ai)
    use_deps = args.deps if args.deps is not None else bool(cfg.deps)
    provider = args.ai_provider or cfg.ai_provider or "anthropic"
    ai_model = args.ai_model or cfg.ai_model
    base_url = args.ai_base_url or cfg.ai_base_url
    if args.min_severity is not None:
        min_sev = args.min_severity
    elif cfg.min_severity is not None:
        min_sev = cfg.min_severity
    else:
        min_sev = Severity.INFO

    result = _collect_findings(
        args.path, cfg, use_ai, use_deps, ai_model,
        ai_provider=provider, ai_base_url=base_url,
        ai_cache=not args.no_ai_cache,
        fix=args.fix, unsafe_fixes=args.unsafe_fixes, console=info,
    )

    # apply config suppressions / ignored rules, then the severity floor
    result.findings = apply_config(result.findings, cfg)
    result.findings, inline_hidden = filter_suppressed(result.findings)
    if inline_hidden:
        result.errors.append(
            f"{inline_hidden} finding(s) suppressed by inline 'xsec: ignore' comments."
        )

    if args.ai_fix and result.findings:
        applied = _run_ai_fix(result.findings, provider, ai_model, base_url, info)
        if applied:
            # re-scan so the report reflects the rewritten code
            result = _collect_findings(
                args.path, cfg, use_ai, use_deps, ai_model,
                ai_provider=provider, ai_base_url=base_url,
                ai_cache=not args.no_ai_cache,
            )
            result.findings = apply_config(result.findings, cfg)
            result.findings, _ = filter_suppressed(result.findings)

    if min_sev > Severity.INFO:
        result.findings = [f for f in result.findings if f.severity >= min_sev]

    # hide findings already recorded in a baseline
    if args.baseline is not None:
        known = load_baseline(Path(args.baseline))
        before = len(result.findings)
        result.findings = filter_new(result.findings, known)
        hidden = before - len(result.findings)
        if hidden:
            result.errors.append(f"{hidden} baselined finding(s) hidden.")

    if args.html:
        args.html.write_text(to_html(result), encoding="utf-8")
        info.print(f"[green]HTML report written to[/] {args.html}")

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


def _run_ai_fix(
    findings, provider: str, ai_model: str | None, base_url: str | None,
    console: Console,
) -> bool:
    """Run the AI fixer over the findings. Returns True if any file changed."""
    # availability gate: same key/package requirements as AI review
    probe = _make_ai_engine(True, provider, ai_model, base_url)
    ok, reason = probe.available()
    if not ok:
        console.print(f"[red]--ai-fix unavailable:[/] {reason}")
        return False

    console.print(f"\n[bold]AI fix:[/] asking {provider} to rewrite affected files…")
    outcomes = fix_findings_with_ai(
        findings, provider=provider, model=probe.model, base_url=base_url,
    )

    applied = False
    for o in outcomes:
        if o.applied:
            applied = True
            console.print(
                f"  [green]✓[/] {o.path} - rewrote file "
                f"({o.fixed_count} static finding(s) verified gone)"
            )
            for line in o.diff.splitlines():
                style = ("green" if line.startswith("+") and not line.startswith("+++")
                         else "red" if line.startswith("-") and not line.startswith("---")
                         else "cyan" if line.startswith("@@") else "dim")
                console.print(f"    {line}", style=style, markup=False, highlight=False)
        else:
            console.print(f"  [yellow]·[/] {o.path} - not fixed: {o.reason}")
    if not outcomes:
        console.print("  [dim]No fixable files (file-level findings only).[/]")
    return applied


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


def run_baseline(args: argparse.Namespace) -> int:
    console = Console()
    if not args.path.exists():
        console.print(f"[red]Path not found:[/] {args.path}")
        return 2

    cfg = Config() if args.no_config else load_config(args.path)
    use_ai = args.ai if args.ai is not None else bool(cfg.ai)
    use_deps = args.deps if args.deps is not None else bool(cfg.deps)
    provider = args.ai_provider or cfg.ai_provider or "anthropic"
    ai_model = args.ai_model or cfg.ai_model
    base_url = args.ai_base_url or cfg.ai_base_url

    result = _collect_findings(
        args.path, cfg, use_ai, use_deps, ai_model,
        ai_provider=provider, ai_base_url=base_url,
        ai_cache=not args.no_ai_cache,
    )
    # record the full, accepted set (config ignores still apply; severity floor doesn't)
    result.findings = apply_config(result.findings, cfg)
    result.findings, _ = filter_suppressed(result.findings)

    count = save_baseline(result.findings, args.output)
    console.print(
        f"[green]Baseline written to[/] {args.output} "
        f"([bold]{count}[/] finding(s) recorded).\n"
        f"Future scans with [bold]--baseline[/] will hide these and show only new ones."
    )
    return 0


def run_key(args: argparse.Namespace) -> int:
    console = Console()
    provider = args.provider
    if args.action == "status":
        console.print(key_status(provider))
        return 0
    if args.action == "clear":
        ok, msg = clear_api_key(provider)
        console.print(("[green]" if ok else "[red]") + msg + "[/]")
        return 0 if ok else 1

    # action == "set": prompt without echoing the key to the screen
    import getpass
    try:
        value = getpass.getpass(f"Paste your {provider} API key (input hidden): ")
    except (EOFError, KeyboardInterrupt):
        console.print("\n[yellow]Cancelled.[/]")
        return 1
    ok, msg = set_api_key(value, provider)
    console.print(("[green]" if ok else "[red]") + msg + "[/]")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "baseline":
        return run_baseline(args)
    if args.command == "key":
        return run_key(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
