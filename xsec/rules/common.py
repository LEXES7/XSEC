"""Pieces shared by every language's rule set.

``RegexRule`` is the one line-matched rule shape, and ``secret_rules()``
builds the hardcoded-credential rules for a language. Secrets look the same
in every language (an AWS key is an AWS key in Python, JS, or Java), so the
patterns live here once and each rule set instantiates them with its own
rule-id prefix.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from xsec.models import Severity


@dataclass
class RegexRule:
    rule_id: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str
    fix: str


_ROTATE = "Remove the credential from source, rotate it, and load it from the environment or a secrets manager."

# (id-suffix, severity, pattern, message) for provider-specific token formats.
# Patterns are anchored to each provider's documented prefix, so they are
# high-precision: a match is almost certainly a real credential.
_TOKEN_PATTERNS: list[tuple[str, Severity, str, str]] = [
    ("SECRET-AWS", Severity.CRITICAL,
     r"\bAKIA[0-9A-Z]{16}\b",
     "Possible hardcoded AWS access key ID."),
    ("SECRET-GITHUB", Severity.CRITICAL,
     r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b",
     "Possible hardcoded GitHub token."),
    ("SECRET-STRIPE", Severity.CRITICAL,
     r"\b[sr]k_live_[A-Za-z0-9]{20,}\b",
     "Possible hardcoded Stripe live secret key."),
    ("SECRET-SLACK", Severity.CRITICAL,
     r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
     "Possible hardcoded Slack token."),
    ("SECRET-GOOGLE", Severity.CRITICAL,
     r"\bAIza[0-9A-Za-z_\-]{35}\b",
     "Possible hardcoded Google API key."),
    ("SECRET-ANTHROPIC", Severity.CRITICAL,
     r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
     "Possible hardcoded Anthropic API key."),
    ("SECRET-OPENAI", Severity.CRITICAL,
     r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b",
     "Possible hardcoded OpenAI API key."),
]

# Generic "password = '...'" assignment. The value must not start with a
# template/placeholder marker ($ { < %) so `password = "${DB_PASS}"` and
# `password = "<your-password>"` don't fire.
_GENERIC_SECRET = (
    r"""(?i)(password|passwd|secret|api[_-]?key|token|access[_-]?key)"""
    r"""\s*[:=]\s*['"](?![$\{<%])[^'"]{6,}['"]"""
)

_PRIVATE_KEY = r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"


def secret_rules(prefix: str) -> list[RegexRule]:
    """The hardcoded-secret rules, with ids like ``{prefix}-SECRET-AWS``."""
    rules = [
        RegexRule(
            f"{prefix}-{suffix}", severity, re.compile(pattern), message, _ROTATE,
        )
        for suffix, severity, pattern, message in _TOKEN_PATTERNS
    ]
    rules.append(RegexRule(
        f"{prefix}-SECRET-GENERIC", Severity.HIGH,
        re.compile(_GENERIC_SECRET),
        "Possible hardcoded secret/credential.",
        "Load secrets from the environment or configuration, not source code.",
    ))
    rules.append(RegexRule(
        f"{prefix}-SECRET-PRIVATE-KEY", Severity.CRITICAL,
        re.compile(_PRIVATE_KEY),
        "Private key material committed in source.",
        "Remove the key, rotate it, and store keys outside the repo.",
    ))
    return rules
