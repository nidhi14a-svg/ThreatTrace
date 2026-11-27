"""
Custom network security rule detecting disabled TLS certificate verification.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class DisabledTlsVerificationRule(BaseCustomRule):
    """Detects HTTP requests made with disabled TLS certificate verification."""

    rule_id: str = "custom.network.disabled-tls-verify"
    title: str = "Disabled TLS Certificate Verification"
    description: str = (
        "HTTP client requests configured with verify=False or disabled TLS checks bypass SSL/TLS "
        "certificate validation, exposing traffic to Man-in-the-Middle (MITM) eavesdropping."
    )
    domain: str = "Network & Communication Security"
    canonical_domain: CanonicalDomainType = "cryptography"
    severity: SeverityType = "high"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py", ".js", ".ts")
    cwe_id: int = 295

    VERIFY_FALSE_PY: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)(?:requests|httpx|urllib3|session)\.[a-z]+\([^)]*verify\s*=\s*False"""
    )
    NODE_TLS_REJECT: ClassVar[re.Pattern[str]] = re.compile(
        r"""NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if self.VERIFY_FALSE_PY.search(line) or self.NODE_TLS_REJECT.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=line.strip(),
                    )
                )
        return findings
