"""Shared, provider-neutral pieces for the AI review engines.

Both the Anthropic engine and the OpenAI-compatible engine ask a model the same
question (find vulnerabilities, return structured JSON) and turn the same JSON
shape into Findings. That common ground lives here so neither engine duplicates
it.
"""

from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from xsec.models import Finding, Severity

# only send the head of very large files
MAX_CHARS = 48_000

# parallel in-flight requests per scan; AI review is network-bound
DEFAULT_CONCURRENCY = 4

SYSTEM_PROMPT = """\
You are a senior application-security engineer reviewing source code for \
vulnerabilities. The code was often written by an AI assistant, which tends to \
introduce: command/SQL injection, unsafe deserialization, missing authn/authz \
checks, hardcoded secrets, SSRF, path traversal, weak crypto, unvalidated \
input reaching dangerous sinks, and race conditions.

Review the provided file and report only *genuine, actionable* security issues. \
Do not report style, performance, or speculative concerns. For each issue give \
the 1-based line number, a severity, a short title, a clear explanation of the \
risk, and a concrete fix. Prefer precision over recall: a false positive costs \
the user trust. If the file has no real security issues, return an empty list.\
"""

# extra instruction for providers that only do generic JSON mode (no schema):
# they need the word "JSON" and an explicit shape in the prompt.
JSON_SHAPE_INSTRUCTION = """\

Respond with ONLY a JSON object of this exact shape (no prose, no markdown):
{"findings": [{"line": <int>, "severity": "critical|high|medium|low|info", \
"title": <string>, "description": <string>, "fix": <string>, "cwe": <string>}]}
If there are no issues, respond with {"findings": []}.\
"""

# JSON Schema used by providers that support structured output (Anthropic).
FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "line": {"type": "integer"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "fix": {"type": "string"},
                    "cwe": {"type": "string"},
                },
                "required": ["line", "severity", "title", "description", "fix", "cwe"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class AiReviewError(Exception):
    """One file's review failed; the message is shown to the user."""


# --- result cache ------------------------------------------------------------
#
# AI review costs money and seconds per file; the same file content with the
# same model and prompt always yields the same answer, so results are cached
# on disk keyed by a content hash. Editing a file changes its hash, which
# invalidates its entry naturally.

def cache_dir() -> Path:
    custom = os.environ.get("XSEC_CACHE_DIR")
    if custom:
        return Path(custom) / "ai"
    xdg = os.environ.get("XDG_CACHE_HOME")
    root = Path(xdg) if xdg else Path.home() / ".cache"
    return root / "xsec" / "ai"


def cache_key(namespace: str, source: str) -> str:
    """Hash of everything that determines the answer: engine+model+prompt+code."""
    material = f"{namespace}\x00{SYSTEM_PROMPT}\x00{source}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _cache_path(key: str) -> Path:
    return cache_dir() / f"{key}.json"


def load_cached(key: str) -> list[dict] | None:
    try:
        return json.loads(_cache_path(key).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def store_cached(key: str, findings: list[Finding]) -> None:
    items = [
        {
            "rule_id": f.rule_id, "severity": f.severity.name, "message": f.message,
            "line": f.line, "fix": f.fix,
        }
        for f in findings
    ]
    try:
        cache_dir().mkdir(parents=True, exist_ok=True)
        _cache_path(key).write_text(json.dumps(items), encoding="utf-8")
    except OSError:
        pass  # caching is best-effort; a read-only home dir shouldn't fail a scan


def _from_cached(items: list[dict], file: str) -> list[Finding]:
    out: list[Finding] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        try:
            sev = Severity[it.get("severity", "MEDIUM")]
        except KeyError:
            sev = Severity.MEDIUM
        out.append(Finding(
            rule_id=str(it.get("rule_id", "AI-REVIEW")), severity=sev,
            message=str(it.get("message", "")), file=file,
            line=int(it.get("line", 0) or 0), engine="ai", fix=it.get("fix"),
        ))
    return out


# --- concurrent driver -------------------------------------------------------

def review_many(
    files: list[Path],
    namespace: str,
    review_one: Callable[[Path, str], list[Finding]],
    errors: list[str],
    use_cache: bool = True,
) -> list[Finding]:
    """Review files concurrently, with the disk cache in front.

    ``review_one(path, source)`` does one provider call and raises
    ``AiReviewError`` on failure. Results come back in ``files`` order so
    reports are deterministic.
    """
    if os.environ.get("XSEC_AI_CACHE", "").strip() == "0":
        use_cache = False
    try:
        workers = max(1, int(os.environ.get("XSEC_AI_CONCURRENCY", DEFAULT_CONCURRENCY)))
    except ValueError:
        workers = DEFAULT_CONCURRENCY

    results: dict[Path, list[Finding]] = {}
    pending: list[tuple[Path, str, str]] = []  # (path, source, cache key)

    for path in files:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        key = cache_key(namespace, source)
        cached = load_cached(key) if use_cache else None
        if cached is not None:
            results[path] = _from_cached(cached, str(path))
        else:
            pending.append((path, source, key))

    if pending:
        with ThreadPoolExecutor(max_workers=min(workers, len(pending))) as pool:
            futures = {
                pool.submit(review_one, path, source): (path, key)
                for path, source, key in pending
            }
            for future in as_completed(futures):
                path, key = futures[future]
                try:
                    found = future.result()
                except AiReviewError as exc:
                    errors.append(f"AI review failed for {path}: {exc}")
                    continue
                results[path] = found
                if use_cache:
                    store_cached(key, found)

    return [f for path in files if path in results for f in results[path]]


def parse_findings(raw: dict, file: str) -> list[Finding]:
    """Turn the model's JSON into Findings (skips junk items)."""
    out: list[Finding] = []
    for item in raw.get("findings", []):
        if not isinstance(item, dict) or "title" not in item:
            continue
        sev = _SEV_MAP.get(str(item.get("severity", "")).lower(), Severity.MEDIUM)
        cwe = item.get("cwe") or None
        rule_id = f"AI-{cwe}" if cwe else "AI-REVIEW"
        msg = item["title"]
        if item.get("description"):
            msg = f"{item['title']} - {item['description']}"
        out.append(Finding(
            rule_id=rule_id,
            severity=sev,
            message=msg,
            file=file,
            line=int(item.get("line", 0) or 0),
            engine="ai",
            fix=item.get("fix"),
        ))
    return out
