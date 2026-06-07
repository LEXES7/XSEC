"""Dependency / CVE scanner.

Most real-world breaches come from a known-vulnerable *version of a package*
you depend on, not from your own code. This engine reads dependency manifests
(requirements.txt, package.json) and checks each pinned version against the
OSV.dev database (https://osv.dev), Google's free open vulnerability feed.

Like the AI engine it is **opt-in** (--deps): it sends your package names and
versions to OSV over the network, so it stays off by default. No API key is
needed. Parsing is pure and unit-tested; only the lookup touches the network.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from xsec.engines.base import Engine
from xsec.models import Finding, Severity
from xsec.netutil import ssl_context

_OSV_URL = "https://api.osv.dev/v1/querybatch"
_TIMEOUT = 30

# manifest filename -> OSV ecosystem name
_MANIFESTS = {
    "requirements.txt": "PyPI",
    "package.json": "npm",
}


@dataclass
class Dep:
    name: str
    version: str
    ecosystem: str          # "PyPI" / "npm"
    manifest: str           # file it came from
    line: int = 0


def parse_requirements(text: str, manifest: str = "requirements.txt") -> list[Dep]:
    """Parse pip requirements. Only exact pins (name==version) can be checked."""
    deps: list[Dep] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):  # skip blanks, -r, -e, options
            continue
        if "==" not in line:                  # need an exact version for OSV
            continue
        name, _, version = line.partition("==")
        name = name.strip()
        # drop extras/markers: "pkg[extra]==1.0 ; python_version<'3'"
        name = name.split("[", 1)[0].strip()
        version = version.split(";", 1)[0].split()[0].strip() if version.strip() else ""
        if name and version:
            deps.append(Dep(name, version, "PyPI", manifest, lineno))
    return deps


def parse_package_json(text: str, manifest: str = "package.json") -> list[Dep]:
    """Parse npm dependencies. Strips ^ ~ >= range prefixes to a base version."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    deps: list[Dep] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            version = _clean_npm_version(spec)
            if version:
                deps.append(Dep(name, version, "npm", manifest))
    return deps


def _clean_npm_version(spec: object) -> str:
    """Turn an npm version spec into a concrete version, or "" if we can't.

    Handles "^1.2.3", "~1.2.3", ">=1.2.3", "1.2.3". Skips ranges/tags/urls
    ("*", "latest", "github:...", "1 || 2") we can't resolve to one version.
    """
    if not isinstance(spec, str):
        return ""
    s = spec.strip().lstrip("^~>=< v").strip()
    if not s or " " in s or "||" in s or "/" in s or ":" in s:
        return ""
    # must look like a dotted numeric version
    head = s.split("-", 1)[0]
    if head and all(part.isdigit() for part in head.split(".") if part):
        return s
    return ""


def parse_osv_batch(deps: list[Dep], response: dict) -> list[Finding]:
    """Turn an OSV querybatch response into Findings, aligned to ``deps``.

    OSV returns results in the same order as the queries we sent. Pure, so it
    is tested without any network call.
    """
    results = response.get("results", [])
    findings: list[Finding] = []
    for dep, result in zip(deps, results):
        vulns = (result or {}).get("vulns") or []
        if not vulns:
            continue
        ids = ", ".join(v.get("id", "?") for v in vulns)
        findings.append(Finding(
            rule_id="DEP-VULN",
            severity=Severity.HIGH,  # OSV listing = known advisory; treat as high
            message=(
                f"{dep.name}@{dep.version} ({dep.ecosystem}) has "
                f"{len(vulns)} known vulnerabilit(y/ies): {ids}"
            ),
            file=dep.manifest,
            line=dep.line,
            engine="deps",
            fix=f"Upgrade {dep.name} to a patched version. See https://osv.dev/list?q={dep.name}",
        ))
    return findings


class DepsEngine(Engine):
    name = "deps"

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled
        self.errors: list[str] = []

    def available(self) -> tuple[bool, str]:
        if not self.enabled:
            return False, "not enabled (pass --deps)"
        return True, ""

    def analyze(self, files: list[Path]) -> list[Finding]:
        deps = self._collect_deps(files)
        if not deps:
            return []
        try:
            response = self._query_osv(deps)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.errors.append(f"Dependency check failed (network): {exc}")
            return []
        return parse_osv_batch(deps, response)

    def _collect_deps(self, files: list[Path]) -> list[Dep]:
        deps: list[Dep] = []
        for path in files:
            ecosystem = _MANIFESTS.get(path.name)
            if not ecosystem:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if path.name == "requirements.txt":
                deps.extend(parse_requirements(text, str(path)))
            elif path.name == "package.json":
                deps.extend(parse_package_json(text, str(path)))
        return deps

    def _query_osv(self, deps: list[Dep]) -> dict:
        queries = [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
            for d in deps
        ]
        body = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            _OSV_URL, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=ssl_context()) as resp:
            return json.loads(resp.read().decode("utf-8"))
