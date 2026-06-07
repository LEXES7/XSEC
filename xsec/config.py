"""Project configuration via an ``.xsec.toml`` file.

Drop an ``.xsec.toml`` at your project root to set defaults and quiet down
known/accepted findings, so you don't retype flags or drown in noise:

    [scan]
    min_severity = "MEDIUM"   # default floor (CLI --min-severity overrides)
    ai = false                # enable engines by default
    deps = false

    [ignore]
    paths = ["examples/", "tests/"]   # glob patterns; skip these files
    rules = ["PY-WEAK-HASH"]          # never report these rule IDs

    [[suppress]]                      # silence one rule in one place
    rule = "PY-EVAL"
    path = "scripts/repl.py"
    reason = "intentional REPL"

CLI flags always win over the file. Parsing is pure and unit-tested.
"""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from xsec.models import Finding, Severity

CONFIG_NAME = ".xsec.toml"


@dataclass
class Suppression:
    rule: str
    path: str | None = None   # glob; if None, applies everywhere
    reason: str = ""


@dataclass
class Config:
    min_severity: Severity | None = None
    ai: bool | None = None
    deps: bool | None = None
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_base_url: str | None = None
    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: list[str] = field(default_factory=list)
    suppressions: list[Suppression] = field(default_factory=list)

    def is_path_ignored(self, file: str) -> bool:
        return any(_path_matches(file, pat) for pat in self.ignore_paths)

    def is_suppressed(self, finding: Finding) -> bool:
        if any(fnmatch.fnmatch(finding.rule_id, pat) for pat in self.ignore_rules):
            return True
        for s in self.suppressions:
            if not fnmatch.fnmatch(finding.rule_id, s.rule):
                continue
            if s.path is None or _path_matches(finding.file, s.path):
                return True
        return False


def _path_matches(file: str, pattern: str) -> bool:
    """Match a file against a path glob.

    A trailing "/" (e.g. "examples/") means "anything under that directory".
    Otherwise standard glob rules apply, matched against the path and its tail.
    """
    norm = file.replace("\\", "/")
    pat = pattern.replace("\\", "/")
    if pat.endswith("/"):
        needle = pat.rstrip("/")
        parts = norm.split("/")
        return needle in parts or norm.startswith(needle + "/")
    return fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(norm, f"*/{pat}")


def parse_config(text: str) -> Config:
    """Parse TOML text into a Config. Unknown keys are ignored."""
    data = tomllib.loads(text)
    cfg = Config()

    scan = data.get("scan", {})
    if isinstance(scan, dict):
        if "min_severity" in scan:
            try:
                cfg.min_severity = Severity[str(scan["min_severity"]).upper()]
            except KeyError:
                pass
        if isinstance(scan.get("ai"), bool):
            cfg.ai = scan["ai"]
        if isinstance(scan.get("deps"), bool):
            cfg.deps = scan["deps"]

    ai = data.get("ai", {})
    if isinstance(ai, dict):
        if isinstance(ai.get("provider"), str):
            cfg.ai_provider = ai["provider"]
        if isinstance(ai.get("model"), str):
            cfg.ai_model = ai["model"]
        if isinstance(ai.get("base_url"), str):
            cfg.ai_base_url = ai["base_url"]

    ignore = data.get("ignore", {})
    if isinstance(ignore, dict):
        cfg.ignore_paths = [str(p) for p in ignore.get("paths", []) if isinstance(p, str)]
        cfg.ignore_rules = [str(r) for r in ignore.get("rules", []) if isinstance(r, str)]

    for item in data.get("suppress", []):
        if isinstance(item, dict) and "rule" in item:
            cfg.suppressions.append(Suppression(
                rule=str(item["rule"]),
                path=str(item["path"]) if item.get("path") else None,
                reason=str(item.get("reason", "")),
            ))

    return cfg


def find_config(start: Path) -> Path | None:
    """Look for .xsec.toml at ``start`` (or its dir) and each parent."""
    start = start.resolve()
    here = start if start.is_dir() else start.parent
    for directory in [here, *here.parents]:
        candidate = directory / CONFIG_NAME
        if candidate.is_file():
            return candidate
    return None


def load_config(start: Path) -> Config:
    """Find and load config near ``start``; empty Config if none/!parseable."""
    path = find_config(start)
    if path is None:
        return Config()
    try:
        return parse_config(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return Config()


def apply_config(findings: list[Finding], cfg: Config) -> list[Finding]:
    """Drop findings that are ignored-by-path or suppressed."""
    return [
        f for f in findings
        if not cfg.is_path_ignored(f.file) and not cfg.is_suppressed(f)
    ]
