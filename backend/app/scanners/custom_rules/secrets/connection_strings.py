"""
Custom rule detecting sensitive database and service connection strings with credentials.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class DatabaseConnectionStringRule(BaseCustomRule):
    """Detects database URIs with embedded cleartext credentials."""

    rule_id: str = "custom.secrets.database-connection-string"
    title: str = "Database Connection String with Credentials"
    description: str = (
        "A database or broker connection string with embedded cleartext username and password was detected. "
        "Store connection credentials in environment variables or an isolated configuration vault."
    )
    domain: str = "Secrets & Sensitive Information Management"
    canonical_domain: CanonicalDomainType = "secrets"
    severity: SeverityType = "critical"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py", ".js", ".ts", ".env", ".json", ".yaml", ".yml")
    cwe_id: int = 798

    CONN_STRING_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://([^:]+):([^@\s'"]+)@([a-zA-Z0-9_\-\.]+)(?::\d+)?(?:/[^\s'"]*)?"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            match = self.CONN_STRING_PATTERN.search(line)
            if match:
                user = match.group(1)
                password = match.group(2)
                # Ignore placeholders like user:password or postgres:postgres in example/test
                if password.lower() in ("password", "pass", "xxx", "placeholder", "changeme", ""):
                    continue

                # Redact password in evidence
                redacted_line = line.replace(password, "********").strip()
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=redacted_line,
                    )
                )
        return findings
