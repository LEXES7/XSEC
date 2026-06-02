"""The Python SAST rules.

Two kinds: AST rules (a function that looks at a node and yields findings)
and regex rules (a pattern matched line by line). AST rules are precise;
regex is for secrets and other text we don't need a parse tree for.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, Iterator

from xsec.models import Finding, Severity


# --- AST rules ---------------------------------------------------------------

AstCheck = Callable[[ast.AST], Iterator[Finding]]


def _call_name(node: ast.Call) -> str:
    # dotted name of the call target, e.g. "os.system" or "eval"
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        cur = func.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _kwarg(node: ast.Call, name: str) -> ast.expr | None:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _make(node: ast.AST, rule_id: str, sev: Severity, msg: str, fix: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=sev,
        message=msg,
        file="",  # engine fills this in
        line=getattr(node, "lineno", 0),
        column=getattr(node, "col_offset", 0),
        engine="sast",
        fix=fix,
    )


def _check_dangerous_calls(node: ast.AST) -> Iterator[Finding]:
    if not isinstance(node, ast.Call):
        return
    name = _call_name(node)

    if name in {"eval", "exec"}:
        yield _make(
            node, "PY-EVAL", Severity.HIGH,
            f"Use of `{name}` can execute arbitrary code.",
            "Avoid eval/exec on dynamic data. Use ast.literal_eval or explicit parsing.",
        )

    if name in {"os.system", "os.popen"}:
        yield _make(
            node, "PY-OS-SYSTEM", Severity.HIGH,
            f"`{name}` runs a shell command - risk of command injection.",
            "Use subprocess.run([...]) with a list of args and shell=False.",
        )

    if name in {"pickle.load", "pickle.loads"}:
        yield _make(
            node, "PY-PICKLE", Severity.HIGH,
            "Deserializing with pickle can execute arbitrary code.",
            "Use json for untrusted data, or a safe serialization format.",
        )

    if name in {"yaml.load"} and _kwarg(node, "Loader") is None:
        yield _make(
            node, "PY-YAML-LOAD", Severity.HIGH,
            "yaml.load without a safe Loader can construct arbitrary objects.",
            "Use yaml.safe_load(...) instead.",
        )

    if name.startswith("subprocess.") and _is_true(_kwarg(node, "shell")):
        yield _make(
            node, "PY-SUBPROCESS-SHELL", Severity.HIGH,
            "subprocess called with shell=True - risk of command injection.",
            "Pass args as a list and drop shell=True.",
        )

    # requests / httpx called with verify=False
    if _is_false(_kwarg(node, "verify")):
        yield _make(
            node, "PY-TLS-VERIFY", Severity.MEDIUM,
            "TLS certificate verification disabled (verify=False).",
            "Remove verify=False; fix the underlying certificate trust issue.",
        )

    if name in {"hashlib.md5", "hashlib.sha1"}:
        yield _make(
            node, "PY-WEAK-HASH", Severity.LOW,
            f"`{name}` is a weak hash unsuitable for security use.",
            "Use hashlib.sha256 or a dedicated password hash (bcrypt/argon2).",
        )


def _check_flask_debug(node: ast.AST) -> Iterator[Finding]:
    # app.run(debug=True) exposes the Werkzeug debugger console
    if not isinstance(node, ast.Call):
        return
    if _call_name(node).endswith(".run") and _is_true(_kwarg(node, "debug")):
        yield _make(
            node, "PY-FLASK-DEBUG", Severity.MEDIUM,
            "Flask/Werkzeug run with debug=True exposes an interactive debugger.",
            "Never enable debug=True in production.",
        )


AST_RULES: list[AstCheck] = [
    _check_dangerous_calls,
    _check_flask_debug,
]


# --- Regex rules -------------------------------------------------------------

@dataclass
class RegexRule:
    rule_id: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str
    fix: str


REGEX_RULES: list[RegexRule] = [
    RegexRule(
        "PY-SECRET-AWS", Severity.CRITICAL,
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Possible hardcoded AWS access key ID.",
        "Move credentials to environment variables or a secrets manager.",
    ),
    RegexRule(
        "PY-SECRET-GENERIC", Severity.HIGH,
        re.compile(
            r"""(?i)(password|passwd|secret|api[_-]?key|token)\s*=\s*['"][^'"]{6,}['"]"""
        ),
        "Possible hardcoded secret/credential.",
        "Load secrets from the environment, not source code.",
    ),
    RegexRule(
        "PY-SECRET-PRIVATE-KEY", Severity.CRITICAL,
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "Private key material committed in source.",
        "Remove the key, rotate it, and store keys outside the repo.",
    ),
]
