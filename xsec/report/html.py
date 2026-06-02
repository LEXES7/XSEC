from __future__ import annotations

import html
import os
from collections import defaultdict
from datetime import datetime

from xsec import __version__
from xsec.models import ScanResult, Severity

_SEV_COLOR = {
    Severity.CRITICAL: "#7f1d1d",
    Severity.HIGH: "#dc2626",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#0891b2",
    Severity.INFO: "#6b7280",
}

_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI",
  Roboto, Helvetica, Arial, sans-serif; background: #0f1115; color: #e5e7eb; }
header { padding: 28px 32px; border-bottom: 1px solid #232733;
  display: flex; align-items: baseline; gap: 14px; }
header h1 { margin: 0; font-size: 22px; letter-spacing: .5px; }
header .meta { color: #8b91a1; font-size: 13px; }
.wrap { padding: 24px 32px 64px; max-width: 1100px; margin: 0 auto; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 8px 0 28px; }
.card { flex: 1 1 120px; background: #161922; border: 1px solid #232733;
  border-radius: 10px; padding: 14px 16px; }
.card .n { font-size: 26px; font-weight: 700; }
.card .l { font-size: 12px; text-transform: uppercase; letter-spacing: .6px;
  color: #8b91a1; margin-top: 2px; }
.file { margin: 28px 0 10px; font-size: 14px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
.file .fname { color: #e5e7eb; font-weight: 600; }
.file .fdir { color: #6b7280; font-size: 12px; }
.finding { background: #161922; border: 1px solid #232733; border-left-width: 4px;
  border-radius: 8px; padding: 14px 16px; margin: 10px 0; }
.finding .top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.badge { font-size: 11px; font-weight: 700; letter-spacing: .5px;
  padding: 2px 8px; border-radius: 999px; color: #fff; }
.rule { font-family: ui-monospace, monospace; font-size: 12px; color: #9aa3b2; }
.lineno { font-family: ui-monospace, monospace; font-size: 12px; font-weight: 600;
  color: #cbd5e1; background: #232733; padding: 2px 8px; border-radius: 6px; }
.loc { margin-left: auto; font-family: ui-monospace, monospace; font-size: 12px;
  color: #6b7280; }
.msg { margin: 10px 0 0; }
.eng { font-size: 11px; color: #6b7280; }
pre.snippet { display: flex; background: #0b0d12; border: 1px solid #232733;
  border-radius: 6px; padding: 0; overflow-x: auto; margin: 10px 0 0; font-size: 13px;
  font-family: ui-monospace, monospace; color: #d1d5db; }
pre.snippet .ln { flex: 0 0 auto; min-width: 38px; text-align: right;
  padding: 8px 10px; margin-right: 12px; color: #6b7280;
  background: #11141b; border-right: 1px solid #232733; user-select: none; }
pre.snippet .code { padding: 8px 12px 8px 0; white-space: pre; }
.fix { margin: 8px 0 0; padding: 8px 12px; background: #0c1f17;
  border: 1px solid #14532d; border-radius: 6px; color: #86efac; font-size: 13px; }
.fix b { color: #bbf7d0; }
.clean { text-align: center; padding: 60px 0; color: #86efac; font-size: 20px; }
.errors { margin-top: 28px; color: #fbbf24; font-size: 13px; }
footer { text-align: center; color: #4b5563; font-size: 12px; padding: 24px; }
"""


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def _summary_cards(result: ScanResult) -> str:
    counts = result.counts()
    cards = [f'<div class="card"><div class="n">{result.files_scanned}</div>'
             f'<div class="l">files</div></div>',
             f'<div class="card"><div class="n">{len(result.findings)}</div>'
             f'<div class="l">findings</div></div>']
    for sev in sorted(Severity, reverse=True):
        if counts[sev]:
            color = _SEV_COLOR[sev]
            cards.append(
                f'<div class="card" style="border-color:{color}">'
                f'<div class="n" style="color:{color}">{counts[sev]}</div>'
                f'<div class="l">{sev}</div></div>'
            )
    return '<div class="cards">' + "".join(cards) + "</div>"


def _finding_html(f) -> str:
    color = _SEV_COLOR.get(f.severity, "#6b7280")
    line_label = f"Line {f.line}" if f.line else "—"
    if f.line and f.column:
        line_label += f", Col {f.column}"

    parts = [f'<div class="finding" style="border-left-color:{color}">']
    parts.append('<div class="top">')
    parts.append(f'<span class="badge" style="background:{color}">{f.severity}</span>')
    parts.append(f'<span class="lineno">{_esc(line_label)}</span>')
    parts.append(f'<span class="rule">{_esc(f.rule_id)}</span>')
    parts.append(f'<span class="eng">via {_esc(f.engine)}</span>')
    parts.append('</div>')
    parts.append(f'<p class="msg">{_esc(f.message)}</p>')
    if f.snippet:
        # the offending line, with a line-number gutter
        ln = str(f.line) if f.line else "·"
        parts.append(
            f'<pre class="snippet"><span class="ln">{ln}</span>'
            f'<span class="code">{_esc(f.snippet)}</span></pre>'
        )
    if f.fix:
        parts.append(f'<div class="fix"><b>Fix:</b> {_esc(f.fix)}</div>')
    parts.append('</div>')
    return "".join(parts)


def _short_path(p: str) -> tuple[str, str]:
    # (filename, directory), directory relative to cwd when possible
    name = os.path.basename(p)
    directory = os.path.dirname(p)
    if directory:
        try:
            rel = os.path.relpath(directory)
            if not rel.startswith(".."):
                directory = rel
        except ValueError:
            pass
    return name, directory


def to_html(result: ScanResult) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    body: list[str] = [_summary_cards(result)]

    if not result.findings:
        body.append('<div class="clean">✓ No findings — code looks clean.</div>')
    else:
        by_file: dict[str, list] = defaultdict(list)
        for f in result.sorted():
            by_file[f.file].append(f)
        # files in worst-first order (sorted() already did the ordering)
        for path in dict.fromkeys(f.file for f in result.sorted()):
            name, directory = _short_path(path)
            header = f'<span class="fname">{_esc(name)}</span>'
            if directory:
                header += f' <span class="fdir">— {_esc(directory)}/</span>'
            body.append(f'<div class="file" title="{_esc(path)}">{header}</div>')
            for f in by_file[path]:
                body.append(_finding_html(f))

    if result.errors:
        body.append('<div class="errors">' +
                    "<br>".join("! " + _esc(e) for e in result.errors) + "</div>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>XSEC report</title><style>{_CSS}</style></head>
<body>
<header><h1>XSEC <span class="meta">security report</span></h1>
<span class="meta">v{__version__} · {ts}</span></header>
<div class="wrap">{"".join(body)}</div>
<footer>Generated by XSEC {__version__}</footer>
</body></html>
"""
