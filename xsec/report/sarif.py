from __future__ import annotations

import json

from xsec import __version__
from xsec.models import ScanResult, Severity

# SARIF only has error / warning / note / none
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_sarif(result: ScanResult) -> str:
    rule_ids = sorted({f.rule_id for f in result.findings})
    rules = [
        {"id": rid, "name": rid, "shortDescription": {"text": rid}}
        for rid in rule_ids
    ]

    results = []
    for f in result.sorted():
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message + (f"\nFix: {f.fix}" if f.fix else "")},
            "properties": {"severity": str(f.severity), "engine": f.engine},
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

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "XSEC",
                "version": __version__,
                "informationUri": "https://github.com/",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
