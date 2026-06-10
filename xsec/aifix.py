"""AI-powered auto-fix: ask a model to rewrite a file, verify, then write.

The mechanical fixer (xsec/fix.py) covers patterns with a known safe rewrite.
This engine covers everything else: it sends the file plus its findings to
the AI provider and asks for a corrected version of the whole file.

A model rewrite is never trusted blindly. Before anything touches disk the
candidate must:

* actually differ from the original, with a sane size ratio (a truncated or
  hallucinated-from-scratch response fails immediately);
* parse, for languages we can parse (Python via ``ast``);
* re-scan cleaner than the original: at least one static finding gone and
  **no new static finding introduced**.

Anything that fails any check is discarded and reported, never written.
"""

from __future__ import annotations

import difflib
import json
import tempfile
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from xsec import __version__
from xsec.models import Finding
from xsec.netutil import ssl_context
from xsec.secrets import get_api_key

# whole-file rewrites get unreliable past this size; skip bigger files
MAX_FIX_CHARS = 24_000

_TIMEOUT = 120

FIX_SYSTEM_PROMPT = """\
You are a senior application-security engineer fixing vulnerabilities in one
source file. You receive the file and a list of findings (line, rule, message,
suggested remediation). Rewrite the file so the vulnerabilities are fixed.

Rules:
- Fix the listed findings; keep everything else byte-for-byte identical where
  possible (imports may be added if a fix needs them).
- Preserve behavior, names, signatures, comments, and formatting.
- Never invent new features, refactor unrelated code, or delete functionality.
- Replace hardcoded secrets with environment-variable lookups.
- If a finding cannot be fixed without breaking behavior, leave that code
  unchanged.
Return the complete corrected file.\
"""

FIX_SCHEMA = {
    "type": "object",
    "properties": {"fixed_source": {"type": "string"}},
    "required": ["fixed_source"],
    "additionalProperties": False,
}


@dataclass
class AiFixOutcome:
    path: Path
    applied: bool
    reason: str = ""     # why it was skipped/rejected (when applied is False)
    diff: str = ""       # unified diff (when applied is True)
    fixed_count: int = 0  # static findings removed


def build_fix_request(path: Path, source: str, findings: list[Finding]) -> str:
    lines = [f"File: {path}", "", "Findings to fix:"]
    for f in findings:
        lines.append(f"- line {f.line}: [{f.rule_id}] {f.message}")
        if f.fix:
            lines.append(f"  remediation: {f.fix}")
    lines += ["", "```", source, "```"]
    return "\n".join(lines)


def static_rule_ids(path_name: str, content: str) -> Counter[str]:
    """Rule-id multiset the static engines report for ``content``.

    Writes to a temp file because the static scanners take paths; the suffix
    is preserved so the right rule set runs.
    """
    from xsec.engines.regex_engine import scan_regex_file
    from xsec.engines.sast import scan_python_file

    suffix = Path(path_name).suffix
    with tempfile.NamedTemporaryFile(
        "w", suffix=suffix, encoding="utf-8", delete=False,
    ) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        if suffix == ".py":
            found = scan_python_file(tmp_path)
        else:
            found = scan_regex_file(tmp_path)
        return Counter(f.rule_id for f in found)
    finally:
        tmp_path.unlink(missing_ok=True)


def validate_fix(path: Path, original: str, fixed: str) -> tuple[bool, str, int]:
    """All the safety gates. Returns (ok, reason-if-not, findings removed)."""
    if not fixed or fixed == original:
        return False, "model returned no change", 0
    ratio = len(fixed) / max(len(original), 1)
    if not 0.25 <= ratio <= 4.0:
        return False, f"rewrite size looks wrong ({ratio:.1f}x the original)", 0

    before = static_rule_ids(path.name, original)
    after = static_rule_ids(path.name, fixed)

    if path.suffix == ".py" and after.get("PY-SYNTAX"):
        return False, "rewrite does not parse", 0

    introduced = [r for r in after if after[r] > before.get(r, 0)]
    if introduced:
        return False, f"rewrite introduces new finding(s): {', '.join(sorted(introduced))}", 0

    removed = sum((before - after).values())
    if before.total() and removed == 0:
        return False, "rewrite does not remove any static finding", 0
    return True, "", removed


def _unified_diff(path: Path, original: str, fixed: str) -> str:
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True), fixed.splitlines(keepends=True),
        fromfile=f"{path} (before)", tofile=f"{path} (after)",
    ))


# --- provider calls ----------------------------------------------------------

def _request_fix_anthropic(model: str, user: str) -> str | None:
    import anthropic

    client = anthropic.Anthropic(api_key=get_api_key())
    resp = client.messages.create(
        model=model,
        max_tokens=32_000,
        system=[{"type": "text", "text": FIX_SYSTEM_PROMPT}],
        output_config={"format": {"type": "json_schema", "schema": FIX_SCHEMA}},
        messages=[{"role": "user", "content": user}],
    )
    text = next((b.text for b in resp.content if b.type == "text"), None)
    if not text:
        return None
    return json.loads(text).get("fixed_source")


def _request_fix_openai_compatible(
    model: str, base_url: str, provider: str, user: str,
) -> str | None:
    from xsec.engines.openai_compatible import _loads_lenient

    instruction = (
        '\n\nRespond with ONLY a JSON object: {"fixed_source": "<the complete '
        'corrected file>"}. No prose, no markdown.'
    )
    body = json.dumps({
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": FIX_SYSTEM_PROMPT + instruction},
            {"role": "user", "content": user},
        ],
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {get_api_key(provider)}",
            "User-Agent": f"xsec/{__version__}",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT, context=ssl_context()) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return None
    data = _loads_lenient(content)
    if not isinstance(data, dict):
        return None
    fixed = data.get("fixed_source")
    return fixed if isinstance(fixed, str) else None


def request_fix(
    provider: str, model: str, base_url: str | None, user: str,
) -> str | None:
    if provider == "anthropic":
        return _request_fix_anthropic(model, user)
    if not base_url:
        from xsec.engines.openai_compatible import PROVIDERS
        preset = PROVIDERS.get(provider)
        base_url = preset.base_url if preset else None
    if not base_url:
        return None
    return _request_fix_openai_compatible(model, base_url, provider, user)


# --- driver ------------------------------------------------------------------

def fix_findings_with_ai(
    findings: list[Finding],
    provider: str = "anthropic",
    model: str | None = None,
    base_url: str | None = None,
    request=request_fix,
) -> list[AiFixOutcome]:
    """Group findings by file, ask the model per file, validate, write.

    ``request`` is injectable so tests can run without a provider.
    """
    if model is None and provider == "anthropic":
        from xsec.engines.ai_review import DEFAULT_MODEL
        model = DEFAULT_MODEL

    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if f.line and Path(f.file).is_file():  # skip file-level (deps) findings
            by_file.setdefault(f.file, []).append(f)

    outcomes: list[AiFixOutcome] = []
    for file, file_findings in sorted(by_file.items()):
        path = Path(file)
        try:
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            outcomes.append(AiFixOutcome(path, False, "could not read file"))
            continue
        if len(original) > MAX_FIX_CHARS:
            outcomes.append(AiFixOutcome(
                path, False, f"file too large for a reliable rewrite (>{MAX_FIX_CHARS} chars)",
            ))
            continue

        try:
            fixed = request(
                provider, model or "", base_url,
                build_fix_request(path, original, file_findings),
            )
        except Exception as exc:  # provider/network errors must not stop the run
            outcomes.append(AiFixOutcome(path, False, f"provider error: {exc}"))
            continue
        if fixed is None:
            outcomes.append(AiFixOutcome(path, False, "model returned no fix"))
            continue

        ok, reason, removed = validate_fix(path, original, fixed)
        if not ok:
            outcomes.append(AiFixOutcome(path, False, reason))
            continue

        path.write_text(fixed, encoding="utf-8")
        outcomes.append(AiFixOutcome(
            path, True, diff=_unified_diff(path, original, fixed), fixed_count=removed,
        ))
    return outcomes
