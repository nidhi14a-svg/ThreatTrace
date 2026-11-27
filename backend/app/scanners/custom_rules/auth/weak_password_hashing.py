"""
Custom authentication security rule detecting weak password hashing algorithms.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class WeakPasswordHashingRule(BaseCustomRule):
    """Detects usage of broken hash algorithms (MD5, SHA1) for passwords or security tokens."""

    rule_id: str = "custom.auth.weak-md5-sha1-hashing"
    title: str = "Weak Hash Algorithm (MD5/SHA1)"
    description: str = (
        "MD5 and SHA-1 are cryptographically broken and vulnerable to collision and pre-image attacks. "
        "Use modern password hashing algorithms (bcrypt, Argon2, PBKDF2) or SHA-256/SHA-512 for integrity."
    )
    domain: str = "Authentication & Access Control"
    canonical_domain: CanonicalDomainType = "cryptography"
    severity: SeverityType = "high"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py", ".js", ".ts")
    cwe_id: int = 327

    WEAK_HASH_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)hashlib\.(?:md5|sha1)\s*\(|crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if self.WEAK_HASH_PATTERN.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=line.strip(),
                    )
                )
        return findings
