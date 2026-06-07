"""Dependency engine tests (no network - parsing + response handling only)."""

from __future__ import annotations

from xsec.engines.deps import (
    Dep,
    DepsEngine,
    parse_osv_batch,
    parse_package_json,
    parse_requirements,
)
from xsec.models import Severity


def test_parse_requirements_exact_pins():
    text = """
    # a comment
    flask==2.0.1
    requests == 2.25.0
    django>=3.0          # range, can't check
    -r other.txt
    pkg[extra]==1.2.3 ; python_version < '3.10'
    """
    deps = parse_requirements(text)
    got = {(d.name, d.version) for d in deps}
    assert ("flask", "2.0.1") in got
    assert ("requests", "2.25.0") in got
    assert ("pkg", "1.2.3") in got          # extras stripped
    assert all(d.name != "django" for d in deps)  # ranges skipped
    assert all(d.ecosystem == "PyPI" for d in deps)


def test_parse_package_json_cleans_versions():
    text = """
    {
      "dependencies": { "lodash": "^4.17.20", "axios": "~0.21.1" },
      "devDependencies": { "jest": ">=27.0.0" },
      "optionalDependencies": { "fsevents": "*", "thing": "latest" }
    }
    """
    deps = parse_package_json(text)
    got = {(d.name, d.version) for d in deps}
    assert ("lodash", "4.17.20") in got
    assert ("axios", "0.21.1") in got
    assert ("jest", "27.0.0") in got
    # unresolvable specs are skipped
    assert all(d.name not in {"fsevents", "thing"} for d in deps)
    assert all(d.ecosystem == "npm" for d in deps)


def test_parse_package_json_bad_json_is_empty():
    assert parse_package_json("{ not json") == []


def test_parse_osv_batch_maps_vulns_in_order():
    deps = [
        Dep("flask", "2.0.1", "PyPI", "requirements.txt", 2),
        Dep("safe", "1.0.0", "PyPI", "requirements.txt", 3),
    ]
    response = {"results": [
        {"vulns": [{"id": "GHSA-aaaa"}, {"id": "CVE-2021-1234"}]},
        {},  # no vulns for "safe"
    ]}
    findings = parse_osv_batch(deps, response)
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == "deps"
    assert f.severity is Severity.HIGH
    assert "flask@2.0.1" in f.message
    assert "GHSA-aaaa" in f.message and "CVE-2021-1234" in f.message
    assert f.line == 2


def test_parse_osv_batch_no_vulns():
    deps = [Dep("safe", "1.0.0", "PyPI", "requirements.txt")]
    assert parse_osv_batch(deps, {"results": [{}]}) == []


def test_engine_disabled_by_default():
    ok, reason = DepsEngine().available()
    assert ok is False and "not enabled" in reason
