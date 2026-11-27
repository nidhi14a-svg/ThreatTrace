"""
Custom configuration security rule detecting wildcard CORS with credentials enabled.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class WildcardCorsCredentialsRule(BaseCustomRule):
    """Detects CORS configuration allowing wildcard origins combined with credentials."""

    rule_id: str = "custom.config.wildcard-cors-allow-credentials"
    title: str = "Wildcard CORS with Credentials Allowed"
    description: str = (
        "Configuring CORS with allow_origins=['*'] alongside allow_credentials=True allows arbitrary "
        "third-party websites to make authenticated cross-origin requests and read sensitive responses."
    )
    domain: str = "Dependency & Configuration Security"
    canonical_domain: CanonicalDomainType = "configuration"
    severity: SeverityType = "high"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py", ".js", ".ts")
    cwe_id: int = 942

    CORS_MIDDLEWARE: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)CORSMiddleware"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []

        # Check multi-line pattern in file content
        has_wildcard = 'allow_origins=["*"]' in content.replace(" ", "") or "allow_origins=['*']" in content.replace(" ", "") or 'origin: "*"' in content
        has_credentials = "allow_credentials=True" in content.replace(" ", "") or "credentials: true" in content.lower()

        if has_wildcard and has_credentials:
            for idx, line in enumerate(lines, start=1):
                if 'allow_origins' in line or 'CORSMiddleware' in line:
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line=idx,
                            evidence=line.strip(),
                        )
                    )
                    break
        return findings
