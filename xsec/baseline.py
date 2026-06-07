"""Baseline: record current findings so future scans only show new ones.

Adopting a scanner on an existing codebase is painful because it reports
hundreds of pre-existing issues at once. A baseline fixes that: you snapshot
today's findings to a file (``xsec baseline <path>``), commit it, and from then
on ``--baseline`` hides anything already in the snapshot. Only *new* problems
your changes introduce get reported.

A finding is identified by a stable fingerprint that ignores line numbers, so
edits elsewhere in a file don't make a baselined finding reappear.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from xsec.models import Finding

BASELINE_NAME = ".xsec-baseline.json"


def fingerprint(f: Finding) -> str:
    """Stable ID for a finding: rule + file + the offending code, not the line.

    Line numbers shift as code moves around, so we deliberately leave them out;
    the trimmed snippet is what makes two findings "the same".
    """
    file = f.file.replace("\\", "/")
    # use the basename so the snapshot survives the repo being moved/cloned
    base = os.path.basename(file)
    snippet = (f.snippet or "").strip()
    key = f"{f.rule_id}\x00{base}\x00{snippet}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def build_baseline(findings: list[Finding]) -> dict:
    return {
        "version": 1,
        "fingerprints": sorted({fingerprint(f) for f in findings}),
    }


def save_baseline(findings: list[Finding], path: Path) -> int:
    """Write a baseline file; returns how many distinct findings were recorded."""
    data = build_baseline(findings)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return len(data["fingerprints"])


def load_baseline(path: Path) -> set[str]:
    """Load recorded fingerprints; empty set if missing/unreadable."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    fps = data.get("fingerprints", [])
    return {str(x) for x in fps} if isinstance(fps, list) else set()


def filter_new(findings: list[Finding], known: set[str]) -> list[Finding]:
    """Keep only findings whose fingerprint isn't in the baseline."""
    return [f for f in findings if fingerprint(f) not in known]
