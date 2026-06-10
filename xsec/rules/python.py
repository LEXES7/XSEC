"""The Python SAST rules.

Two kinds: AST rules (a function that looks at a node and yields findings)
and regex rules (a pattern matched line by line). AST rules are precise;
regex is for secrets and other text we don't need a parse tree for.
"""

from __future__ import annotations

import ast
import re
from typing import Callable, Iterator

from xsec.models import Finding, Severity
from xsec.rules.common import RegexRule, secret_rules

__all__ = ["AST_RULES", "REGEX_RULES", "RegexRule"]


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


def _const_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


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

    yield from _check_weak_hash(node, name)


def _check_weak_hash(node: ast.Call, name: str) -> Iterator[Finding]:
    # hashlib.md5(usedforsecurity=False) is an explicit "not for security"
    # declaration (3.9+), so it doesn't get flagged
    if _is_false(_kwarg(node, "usedforsecurity")):
        return
    weak = None
    if name in {"hashlib.md5", "hashlib.sha1"}:
        weak = name
    elif name == "hashlib.new":
        algo = (_const_str(node.args[0] if node.args else None)
                or _const_str(_kwarg(node, "name")) or "").lower()
        if algo in {"md5", "sha1"}:
            weak = f'hashlib.new("{algo}")'
    if weak:
        yield _make(
            node, "PY-WEAK-HASH", Severity.LOW,
            f"`{weak}` is a weak hash unsuitable for security use.",
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


# SQL statement keywords; a dynamic string is only flagged as SQL injection
# when its literal fragments actually look like SQL
_SQL_KEYWORD = re.compile(
    r"\b(?:SELECT\s|INSERT\s+INTO\s|UPDATE\s\w+\sSET\s|DELETE\s+FROM\s"
    r"|DROP\s+TABLE\s|CREATE\s+TABLE\s|ALTER\s+TABLE\s)",
    re.IGNORECASE,
)

# nodes that mean "this value is computed at runtime"
_DYNAMIC_NODES = (ast.Name, ast.Call, ast.Attribute, ast.Subscript)


def _literal_fragments(node: ast.expr) -> str:
    """All constant string pieces inside an expression, joined."""
    return " ".join(
        sub.value for sub in ast.walk(node)
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str)
    )


def _builds_string_dynamically(arg: ast.expr) -> bool:
    """True when the expression assembles a string from runtime values."""
    if isinstance(arg, ast.JoinedStr):  # f-string with at least one {expr}
        return any(isinstance(v, ast.FormattedValue) for v in arg.values)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
        return any(isinstance(sub, _DYNAMIC_NODES) for sub in ast.walk(arg))
    if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "format"):
        return bool(arg.args or arg.keywords)
    return False


def _check_sql_injection(node: ast.AST) -> Iterator[Finding]:
    """cursor.execute(f"... {x}") / ("..." % x) / ("...".format(x)) / ("..." + x)."""
    if not isinstance(node, ast.Call):
        return
    func = node.func
    if not (isinstance(func, ast.Attribute)
            and func.attr in {"execute", "executemany", "executescript"}):
        return
    if not node.args:
        return
    arg = node.args[0]
    if not _builds_string_dynamically(arg):
        return
    if not _SQL_KEYWORD.search(_literal_fragments(arg)):
        return
    yield _make(
        node, "PY-SQL-INJECTION", Severity.HIGH,
        "SQL statement built from runtime values - risk of SQL injection.",
        'Use parameterized queries: cursor.execute("... WHERE id = ?", (value,)).',
    )


def _check_jwt_no_verify(node: ast.AST) -> Iterator[Finding]:
    if not isinstance(node, ast.Call):
        return
    if not _call_name(node).endswith("jwt.decode"):
        return
    fix = 'Verify signatures: jwt.decode(token, key, algorithms=["HS256"]).'
    if _is_false(_kwarg(node, "verify")):
        yield _make(
            node, "PY-JWT-NOVERIFY", Severity.HIGH,
            "JWT decoded with verify=False - the token's signature is not checked.",
            fix,
        )
        return
    opts = _kwarg(node, "options")
    if isinstance(opts, ast.Dict):
        for key, value in zip(opts.keys, opts.values):
            if _const_str(key) == "verify_signature" and _is_false(value):
                yield _make(
                    node, "PY-JWT-NOVERIFY", Severity.HIGH,
                    "JWT decoded with verify_signature disabled - the token's "
                    "signature is not checked.",
                    fix,
                )


def _check_ssl_no_verify(node: ast.AST) -> Iterator[Finding]:
    if not isinstance(node, ast.Call):
        return
    if _call_name(node).endswith("_create_unverified_context"):
        yield _make(
            node, "PY-SSL-NO-VERIFY", Severity.HIGH,
            "ssl._create_unverified_context disables certificate verification.",
            "Use ssl.create_default_context(); fix the trust store instead.",
        )
    cert_reqs = _kwarg(node, "cert_reqs")
    if isinstance(cert_reqs, ast.Attribute) and cert_reqs.attr == "CERT_NONE":
        yield _make(
            node, "PY-SSL-NO-VERIFY", Severity.HIGH,
            "cert_reqs=ssl.CERT_NONE disables certificate verification.",
            "Use ssl.CERT_REQUIRED (the default for client contexts).",
        )


def _check_archive_extractall(node: ast.AST) -> Iterator[Finding]:
    if not isinstance(node, ast.Call):
        return
    name = _call_name(node)
    if not name.endswith(".extractall") or _kwarg(node, "filter") is not None:
        return
    yield _make(
        node, "PY-EXTRACTALL", Severity.MEDIUM,
        "extractall on an untrusted archive can write outside the target "
        "directory (path traversal).",
        "For tar archives pass filter='data' (Python 3.12+), or validate "
        "each member's path before extracting.",
    )


def _check_tempfile_mktemp(node: ast.AST) -> Iterator[Finding]:
    if not isinstance(node, ast.Call):
        return
    if _call_name(node) in {"tempfile.mktemp", "mktemp"}:
        yield _make(
            node, "PY-MKTEMP", Severity.MEDIUM,
            "tempfile.mktemp is racy: the name can be claimed by an attacker "
            "before the file is created.",
            "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
        )


def _check_mark_safe(node: ast.AST) -> Iterator[Finding]:
    if not isinstance(node, ast.Call):
        return
    if _call_name(node).endswith("mark_safe"):
        yield _make(
            node, "PY-MARK-SAFE", Severity.MEDIUM,
            "mark_safe bypasses Django's autoescaping - XSS risk if any input "
            "reaches this string.",
            "Escape user input (django.utils.html.escape / format_html) "
            "instead of marking the whole string safe.",
        )


_XXE_SUFFIXES = (
    "sax.make_parser",
    "minidom.parse", "minidom.parseString",
    "pulldom.parse", "pulldom.parseString",
)


def _check_xml_xxe(node: ast.AST) -> Iterator[Finding]:
    if not isinstance(node, ast.Call):
        return
    name = _call_name(node)
    if any(name == s or name.endswith("." + s) for s in _XXE_SUFFIXES):
        yield _make(
            node, "PY-XXE", Severity.MEDIUM,
            f"`{name}` is vulnerable to XML external-entity (XXE) and "
            "entity-expansion attacks on untrusted input.",
            "Parse untrusted XML with the defusedxml package.",
        )


_PREDICTABLE_RANDOM = {
    "random.random", "random.randint", "random.randrange", "random.choice",
    "random.choices", "random.getrandbits", "random.randbytes",
}


def _check_insecure_random(node: ast.AST) -> Iterator[Finding]:
    if not isinstance(node, ast.Call):
        return
    if _call_name(node) in _PREDICTABLE_RANDOM:
        yield _make(
            node, "PY-INSECURE-RANDOM", Severity.LOW,
            "The random module is predictable - fine for simulations, not for "
            "tokens, passwords, or anything security-sensitive.",
            "Use the secrets module (secrets.token_hex, secrets.choice) for "
            "security purposes.",
        )


_ALL_INTERFACES = {"0.0.0.0", "::"}


def _check_bind_all_interfaces(node: ast.AST) -> Iterator[Finding]:
    if not isinstance(node, ast.Call):
        return
    msg = "Service bound to all network interfaces ({addr!r})."
    fix = 'Bind to "127.0.0.1" unless the service must be reachable externally.'
    host = _const_str(_kwarg(node, "host"))
    if host in _ALL_INTERFACES:
        yield _make(node, "PY-BIND-ALL", Severity.LOW, msg.format(addr=host), fix)
        return
    # sock.bind(("0.0.0.0", port))
    func = node.func
    if (isinstance(func, ast.Attribute) and func.attr == "bind" and node.args
            and isinstance(node.args[0], ast.Tuple) and node.args[0].elts):
        addr = _const_str(node.args[0].elts[0])
        if addr in _ALL_INTERFACES:
            yield _make(node, "PY-BIND-ALL", Severity.LOW, msg.format(addr=addr), fix)


AST_RULES: list[AstCheck] = [
    _check_dangerous_calls,
    _check_flask_debug,
    _check_sql_injection,
    _check_jwt_no_verify,
    _check_ssl_no_verify,
    _check_archive_extractall,
    _check_tempfile_mktemp,
    _check_mark_safe,
    _check_xml_xxe,
    _check_insecure_random,
    _check_bind_all_interfaces,
]


# --- Regex rules -------------------------------------------------------------

# hardcoded credentials look the same in every language; patterns are shared
REGEX_RULES: list[RegexRule] = secret_rules("PY")
