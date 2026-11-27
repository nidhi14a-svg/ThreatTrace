"""
Custom network security rule detecting hardcoded cleartext HTTP external endpoints.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)

IGNORED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "www.w3.org",
    "schemas.xmlsoap.org",
    "json-schema.org",
    "example.com",
    "test",
}


class CleartextHttpEndpointRule(BaseCustomRule):
    """Detects cleartext http:// external URLs where HTTPS should be enforced."""

    rule_id: str = "custom.network.cleartext-http-endpoint"
    title: str = "Cleartext HTTP External URL"
    description: str = (
        "Detected unencrypted http:// URL for an external endpoint. "
        "Sensitive communication and API calls must use encrypted HTTPS transport."
    )
    domain: str = "Network & Communication Security"
    canonical_domain: CanonicalDomainType = "cryptography"
    severity: SeverityType = "medium"
    confidence: ConfidenceType = "medium"
    file_extensions: tuple[str, ...] = (".py", ".js", ".ts", ".env", ".json")
    cwe_id: int = 319

    HTTP_URL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""['"]http://([a-zA-Z0-9_\-\.]+)(?::\d+)?(?:/[^'"]*)?['"]"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            match = self.HTTP_URL_PATTERN.search(line)
            if match:
                host = match.group(1).lower()
                if host in IGNORED_HOSTS or host.endswith(".local") or host.endswith(".internal"):
                    continue

                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=line.strip(),
                    )
                )
        return findings
