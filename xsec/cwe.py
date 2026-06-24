"""Map rule IDs to CWE identifiers (https://cwe.mitre.org).

A CWE id ties a finding to a recognized weakness taxonomy, which is what
GitHub code scanning, security dashboards, and compliance reports key off. The
rule id already names the weakness (``PY-EVAL``, ``JS-CHILD-PROCESS-EXEC``), so
we map by the semantic suffix shared across languages — one entry covers the
Python, JavaScript, and Java variants of the same issue.

The AI engine emits ids like ``AI-CWE-89`` directly; ``cwe_for`` reads those
straight out of the id.
"""

from __future__ import annotations

import re

# weakness-suffix -> (CWE id, short CWE name). The language prefix (PY-/JS-/
# JAVA-) is stripped before lookup, so each weakness is listed once.
_CWE_BY_SUFFIX: dict[str, tuple[int, str]] = {
    # injection
    "EVAL": (95, "Eval Injection"),
    "FUNCTION-CTOR": (95, "Eval Injection"),
    "OS-SYSTEM": (78, "OS Command Injection"),
    "SUBPROCESS-SHELL": (78, "OS Command Injection"),
    "CHILD-PROCESS-EXEC": (78, "OS Command Injection"),
    "RUNTIME-EXEC": (78, "OS Command Injection"),
    "PROCESS-BUILDER-CONCAT": (78, "OS Command Injection"),
    "SQL-CONCAT": (89, "SQL Injection"),
    "SQL-STRING": (89, "SQL Injection"),
    "XXE": (611, "XML External Entity Reference"),
    # xss / output
    "INNERHTML": (79, "Cross-site Scripting"),
    "DOCUMENT-WRITE": (79, "Cross-site Scripting"),
    "MARK-SAFE": (79, "Cross-site Scripting"),
    # deserialization
    "PICKLE": (502, "Deserialization of Untrusted Data"),
    "YAML-LOAD": (502, "Deserialization of Untrusted Data"),
    "DESERIALIZE": (502, "Deserialization of Untrusted Data"),
    # crypto / transport
    "WEAK-HASH": (327, "Use of a Broken or Risky Cryptographic Algorithm"),
    "WEAK-CIPHER": (327, "Use of a Broken or Risky Cryptographic Algorithm"),
    "TLS-VERIFY": (295, "Improper Certificate Validation"),
    "TLS-REJECT": (295, "Improper Certificate Validation"),
    "NO-TLS-VERIFY": (295, "Improper Certificate Validation"),
    "SSL-NO-VERIFY": (295, "Improper Certificate Validation"),
    "JWT-NO-VERIFY": (347, "Improper Verification of Cryptographic Signature"),
    "INSECURE-RANDOM": (330, "Use of Insufficiently Random Values"),
    # secrets
    "SECRET-GENERIC": (798, "Use of Hard-coded Credentials"),
    "SECRET-AWS": (798, "Use of Hard-coded Credentials"),
    "SECRET-GITHUB": (798, "Use of Hard-coded Credentials"),
    "SECRET-STRIPE": (798, "Use of Hard-coded Credentials"),
    "SECRET-SLACK": (798, "Use of Hard-coded Credentials"),
    "SECRET-GOOGLE": (798, "Use of Hard-coded Credentials"),
    "SECRET-ANTHROPIC": (798, "Use of Hard-coded Credentials"),
    "SECRET-OPENAI": (798, "Use of Hard-coded Credentials"),
    "PRIVATE-KEY": (798, "Use of Hard-coded Credentials"),
    # misc
    "EXTRACTALL": (22, "Path Traversal"),
    "MKTEMP": (377, "Insecure Temporary File"),
    "BIND-ALL": (200, "Exposure of Sensitive Information"),
    "FLASK-DEBUG": (489, "Active Debug Code"),
}

_LANG_PREFIXES = ("PY-", "JS-", "JAVA-")
_AI_CWE = re.compile(r"^AI-CWE-(\d+)$", re.IGNORECASE)


def cwe_for(rule_id: str) -> int | None:
    """Return the CWE number for a rule id, or None if unmapped."""
    m = _AI_CWE.match(rule_id)
    if m:
        return int(m.group(1))
    suffix = rule_id
    for prefix in _LANG_PREFIXES:
        if suffix.startswith(prefix):
            suffix = suffix[len(prefix):]
            break
    entry = _CWE_BY_SUFFIX.get(suffix)
    return entry[0] if entry else None


def cwe_name(cwe: int) -> str | None:
    """Return the short name for a CWE number we know about, else None."""
    for num, name in _CWE_BY_SUFFIX.values():
        if num == cwe:
            return name
    return None


def cwe_tag(rule_id: str) -> str | None:
    """Return a display tag like ``CWE-89`` for a rule id, or None."""
    cwe = cwe_for(rule_id)
    return f"CWE-{cwe}" if cwe else None
