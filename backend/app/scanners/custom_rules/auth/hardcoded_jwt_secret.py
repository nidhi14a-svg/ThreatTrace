"""
Custom authentication security rule detecting hardcoded JWT signing secrets.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class HardcodedJwtSecretRule(BaseCustomRule):
    """Detects hardcoded string literal keys passed to jwt.encode or jwt.decode."""

    rule_id: str = "custom.auth.hardcoded-jwt-secret"
    title: str = "Hardcoded JWT Secret Key"
    description: str = (
        "Detected a hardcoded static string used as the signing or verification secret for JWT tokens. "
        "JWT secrets should be securely loaded from environment variables or a dedicated key management service."
    )
    domain: str = "Authentication & Access Control"
    canonical_domain: CanonicalDomainType = "authentication"
    severity: SeverityType = "critical"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py", ".js", ".ts")
    cwe_id: int = 798

    JWT_LITERAL_SECRET: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)jwt\.(?:encode|decode)\s*\([^,]+,\s*['"]([^'"]{4,})['"]"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if "os.getenv" in line or "os.environ" in line or "process.env" in line:
                continue

            match = self.JWT_LITERAL_SECRET.search(line)
            if match:
                raw_secret = match.group(1)
                # Redact the secret in evidence
                redacted_evidence = line.replace(raw_secret, "********").strip()
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=redacted_evidence,
                    )
                )
        return findings
