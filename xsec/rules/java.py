"""Java rules.

Regex rules matched line by line (we don't AST-parse Java). They target the
classic Java vulnerability sinks: runtime command execution, SQL built by
string concatenation, unsafe deserialization, weak crypto/RNG, XXE, and
hardcoded secrets.
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


RULES: list[RegexRule] = [
    RegexRule(
        "JAVA-RUNTIME-EXEC", Severity.HIGH,
        re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("),
        "Runtime.exec runs a system command - risk of command injection.",
        "Use ProcessBuilder with an argument list and validate inputs.",
    ),
    RegexRule(
        "JAVA-PROCESS-BUILDER-CONCAT", Severity.MEDIUM,
        re.compile(r"new\s+ProcessBuilder\s*\([^)]*\+"),
        "ProcessBuilder built from concatenated strings may allow injection.",
        "Pass each argument as a separate list element, not a built string.",
    ),
    RegexRule(
        "JAVA-SQL-CONCAT", Severity.HIGH,
        re.compile(
            r"""(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*['"].*\+"""
        ),
        "SQL built with string concatenation - risk of SQL injection.",
        "Use a PreparedStatement with parameter placeholders (?).",
    ),
    RegexRule(
        "JAVA-DESERIALIZE", Severity.HIGH,
        re.compile(r"new\s+ObjectInputStream\s*\("),
        "Java native deserialization can execute arbitrary code.",
        "Avoid ObjectInputStream on untrusted data; use a safe format like JSON.",
    ),
    RegexRule(
        "JAVA-WEAK-HASH", Severity.LOW,
        re.compile(r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-1)['\"]"),
        "Weak hash (MD5/SHA-1) unsuitable for security use.",
        "Use SHA-256, or bcrypt/PBKDF2/argon2 for passwords.",
    ),
    RegexRule(
        "JAVA-WEAK-CIPHER", Severity.MEDIUM,
        re.compile(r"Cipher\.getInstance\s*\(\s*['\"](?:DES|RC4|DES/|.*ECB)"),
        "Weak or insecure cipher mode (DES/RC4/ECB).",
        "Use AES in GCM mode (AES/GCM/NoPadding) with a random IV.",
    ),
    RegexRule(
        "JAVA-INSECURE-RANDOM", Severity.LOW,
        re.compile(r"new\s+java\.util\.Random\s*\(|=\s*new\s+Random\s*\("),
        "java.util.Random is predictable; not for security tokens.",
        "Use java.security.SecureRandom for anything security-sensitive.",
    ),
    RegexRule(
        "JAVA-XXE", Severity.MEDIUM,
        re.compile(r"DocumentBuilderFactory\.newInstance\s*\(\s*\)"),
        "XML parser may be vulnerable to XXE if external entities aren't disabled.",
        "Disable DOCTYPE/external entities on the factory before parsing.",
    ),
    RegexRule(
        "JAVA-SECRET-GENERIC", Severity.HIGH,
        re.compile(
            r"""(?i)(password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*=\s*['"][^'"]{6,}['"]"""
        ),
        "Possible hardcoded secret/credential.",
        "Load secrets from configuration/environment, not source.",
    ),
    RegexRule(
        "JAVA-SECRET-AWS", Severity.CRITICAL,
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Possible hardcoded AWS access key ID.",
        "Move credentials to environment variables or a secrets manager.",
    ),
    RegexRule(
        "JAVA-PRIVATE-KEY", Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "Private key material committed in source.",
        "Remove the key, rotate it, and store keys outside the repo.",
    ),
]
