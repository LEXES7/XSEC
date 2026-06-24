"""Tests for CWE mapping and its appearance in SARIF/JSON."""

from __future__ import annotations

import json

from xsec.cwe import cwe_for, cwe_name, cwe_tag
from xsec.models import Finding, ScanResult, Severity
from xsec.report.console import to_json
from xsec.report.sarif import to_sarif


def test_maps_language_prefixed_rules_to_same_cwe():
    # the Python, JS, and Java command-injection rules all map to CWE-78
    assert cwe_for("PY-OS-SYSTEM") == 78
    assert cwe_for("JS-CHILD-PROCESS-EXEC") == 78
    assert cwe_for("JAVA-RUNTIME-EXEC") == 78


def test_maps_sql_and_secrets():
    assert cwe_for("JAVA-SQL-CONCAT") == 89
    assert cwe_for("PY-SECRET-AWS") == 798
    assert cwe_for("JS-SECRET-GENERIC") == 798


def test_reads_cwe_from_ai_rule_id():
    assert cwe_for("AI-CWE-89") == 89
    assert cwe_for("ai-cwe-502") == 502


def test_unmapped_rule_is_none():
    assert cwe_for("PY-TOTALLY-UNKNOWN") is None
    assert cwe_tag("PY-TOTALLY-UNKNOWN") is None


def test_tag_and_name():
    assert cwe_tag("PY-EVAL") == "CWE-95"
    assert cwe_name(89) == "SQL Injection"


def _result() -> ScanResult:
    return ScanResult(findings=[
        Finding("PY-OS-SYSTEM", Severity.HIGH, "cmd injection", "a.py", 3),
        Finding("PY-NO-CWE-RULE", Severity.LOW, "misc", "a.py", 5),
    ], files_scanned=1)


def test_json_includes_cwe():
    data = json.loads(to_json(_result()))
    by_rule = {f["rule_id"]: f for f in data["findings"]}
    assert by_rule["PY-OS-SYSTEM"]["cwe"] == "CWE-78"
    assert by_rule["PY-NO-CWE-RULE"]["cwe"] is None


def test_sarif_includes_cwe_taxonomy():
    doc = json.loads(to_sarif(_result()))
    run = doc["runs"][0]
    # the finding carries a cwe property
    res = next(r for r in run["results"] if r["ruleId"] == "PY-OS-SYSTEM")
    assert res["properties"]["cwe"] == "CWE-78"
    # the rule descriptor references the CWE
    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "PY-OS-SYSTEM")
    assert rule["properties"]["cwe"] == "CWE-78"
    # the CWE taxonomy is declared
    taxa = run["taxonomies"][0]["taxa"]
    assert any(t["id"] == "CWE-78" for t in taxa)
    assert all("helpUri" in t for t in taxa)
