"""JavaScript / TypeScript rules.

Python ships an AST parser for Python but not for JS, so these are regex
rules matched line by line. They target the unsafe patterns AI tends to emit
in JS/TS: eval, code injection sinks, child_process with a string command,
DOM XSS sinks, weak crypto, and hardcoded secrets.

Regex can't understand code structure, so we keep patterns tight to avoid
false positives, and these run alongside (not instead of) the AI engine.
"""

from __future__ import annotations

import re

from xsec.models import Severity
from xsec.rules.common import RegexRule, secret_rules

RULES: list[RegexRule] = [
    RegexRule(
        "JS-EVAL", Severity.HIGH,
        re.compile(r"\beval\s*\("),
        "Use of eval() can execute arbitrary code.",
        "Avoid eval. Parse data with JSON.parse or use explicit logic.",
    ),
    RegexRule(
        "JS-FUNCTION-CTOR", Severity.HIGH,
        re.compile(r"\bnew\s+Function\s*\("),
        "new Function(...) executes code built from a string.",
        "Avoid the Function constructor on dynamic input.",
    ),
    RegexRule(
        "JS-CHILD-PROCESS-EXEC", Severity.HIGH,
        re.compile(r"\b(?:cp|child_process)?\.?exec\s*\(\s*[`'\"].*\$\{?"),
        "child_process.exec with an interpolated string risks command injection.",
        "Use execFile/spawn with an argument array, not a built command string.",
    ),
    RegexRule(
        "JS-INNERHTML", Severity.MEDIUM,
        re.compile(r"\.innerHTML\s*="),
        "Assigning to innerHTML can introduce DOM XSS.",
        "Use textContent, or sanitize HTML before inserting it.",
    ),
    RegexRule(
        "JS-DOCUMENT-WRITE", Severity.MEDIUM,
        re.compile(r"\bdocument\.write\s*\("),
        "document.write can introduce XSS and is discouraged.",
        "Build DOM nodes or use textContent instead.",
    ),
    RegexRule(
        "JS-WEAK-HASH", Severity.LOW,
        re.compile(r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)"),
        "Weak hash (md5/sha1) unsuitable for security use.",
        "Use sha256, or bcrypt/scrypt/argon2 for passwords.",
    ),
    RegexRule(
        "JS-TLS-REJECT", Severity.HIGH,
        re.compile(r"rejectUnauthorized\s*:\s*false"),
        "TLS certificate verification disabled (rejectUnauthorized: false).",
        "Remove it; fix the underlying certificate trust instead.",
    ),
    RegexRule(
        "JS-NO-TLS-VERIFY", Severity.HIGH,
        re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
        "Disabling NODE_TLS_REJECT_UNAUTHORIZED turns off all TLS verification.",
        "Never disable TLS verification process-wide.",
    ),
    RegexRule(
        "JS-SQL-CONCAT", Severity.HIGH,
        re.compile(r"\.(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)"),
        "SQL/query string built from runtime values - risk of injection.",
        "Use parameterized queries: db.query('... WHERE id = ?', [value]).",
    ),
    RegexRule(
        "JS-REACT-DANGEROUS-HTML", Severity.MEDIUM,
        re.compile(r"dangerouslySetInnerHTML\s*[=:]"),
        "dangerouslySetInnerHTML renders raw HTML - XSS risk if any input reaches it.",
        "Render text via JSX, or sanitize the HTML (e.g. DOMPurify) first.",
    ),
    # hardcoded credentials look the same in every language; patterns are shared
    *secret_rules("JS"),
]
