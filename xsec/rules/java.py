"""Java rules.

Regex rules matched line by line (we don't AST-parse Java). They target the
classic Java vulnerability sinks: runtime command execution, SQL built by
string concatenation, unsafe deserialization, weak crypto/RNG, XXE, and
hardcoded secrets.
"""

from __future__ import annotations

import re

from xsec.models import Severity
from xsec.rules.common import RegexRule, secret_rules

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
    # hardcoded credentials look the same in every language; patterns are shared
    *secret_rules("JAVA"),
]
