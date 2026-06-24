from __future__ import annotations

import json

from xsec import __version__
from xsec.cwe import cwe_for, cwe_name
from xsec.models import ScanResult, Severity

# SARIF only has error / warning / note / none
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_CWE_URI = "https://cwe.mitre.org/data/definitions/{}.html"


def to_sarif(result: ScanResult) -> str:
    rule_ids = sorted({f.rule_id for f in result.findings})

    # build the rule descriptors, tagging each with its CWE so code-scanning
    # dashboards can group findings by weakness
    rules = []
    cwes_seen: dict[int, str] = {}
    for rid in rule_ids:
        rule: dict = {"id": rid, "name": rid, "shortDescription": {"text": rid}}
        cwe = cwe_for(rid)
        if cwe is not None:
            cwes_seen[cwe] = cwe_name(cwe) or f"CWE-{cwe}"
            rule["properties"] = {"cwe": f"CWE-{cwe}", "tags": [f"external/cwe/cwe-{cwe}"]}
            rule["relationships"] = [{
                "target": {
                    "id": f"CWE-{cwe}",
                    "toolComponent": {"name": "CWE"},
                },
                "kinds": ["superset"],
            }]
        rules.append(rule)

    results = []
    for f in result.sorted():
        props = {"severity": str(f.severity), "engine": f.engine}
        cwe = cwe_for(f.rule_id)
        if cwe is not None:
            props["cwe"] = f"CWE-{cwe}"
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message + (f"\nFix: {f.fix}" if f.fix else "")},
            "properties": props,
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {
                        "startLine": max(f.line, 1),
                        "startColumn": max(f.column, 1),
                    },
                }
            }],
        })

    driver = {
        "name": "XSEC",
        "version": __version__,
        "informationUri": "https://github.com/LEXES7/XSEC",
        "rules": rules,
    }

    run: dict = {"tool": {"driver": driver}, "results": results}

    # declare the CWE taxonomy we referenced, per SARIF 2.1.0
    if cwes_seen:
        run["taxonomies"] = [{
            "name": "CWE",
            "organization": "MITRE",
            "shortDescription": {"text": "The MITRE Common Weakness Enumeration"},
            "taxa": [
                {
                    "id": f"CWE-{num}",
                    "name": name,
                    "helpUri": _CWE_URI.format(num),
                }
                for num, name in sorted(cwes_seen.items())
            ],
        }]

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(doc, indent=2)
