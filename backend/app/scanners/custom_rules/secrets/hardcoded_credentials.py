"""
Custom secrets management rules for hardcoded credentials, passwords, and private keys.
"""

import re
from typing import Any, ClassVar

from app.scanners.base_scanner import BaseScanner
from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)

EXACT_PLACEHOLDERS = {
    "123456",
    "12345678",
    "123456789",
    "password",
    "changeme",
    "admin",
    "root",
    "secret",
    "placeholder",
    "example",
    "none",
    "null",
}

PLACEHOLDER_SUBSTRINGS = {
    "your_key",
    "your_api_key",
    "your_token",
    "your_password",
    "placeholder",
    "replace_me",
    "dummy_key",
    "test_key",
    "test_token",
    "test_pass",
}


def _is_placeholder(val: str) -> bool:
    """Check if value is a known mock or template placeholder."""
    cleaned = val.strip().lower()
    if not cleaned or len(cleaned) < 6:
        return True
    if cleaned in EXACT_PLACEHOLDERS:
        return True
    return any(p in cleaned for p in PLACEHOLDER_SUBSTRINGS)


class HardcodedApiKeyRule(BaseCustomRule):
    """Detects hardcoded API keys and authentication tokens assigned to variables."""

    rule_id: str = "custom.secrets.hardcoded-api-key"
    title: str = "Hardcoded API Key or Access Token"
    description: str = (
        "An API key or access token is hardcoded in source code or configuration. "
        "Credentials should be loaded dynamically from environment variables or a secrets manager."
    )
    domain: str = "Secrets & Sensitive Information Management"
    canonical_domain: CanonicalDomainType = "secrets"
    severity: SeverityType = "high"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py", ".js", ".ts", ".env", ".json", ".yaml", ".yml")
    cwe_id: int = 798

    KEY_ASSIGN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)(?:^|[\s,;{(])(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{16,128})['"]"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if "os.getenv" in line or "os.environ" in line or "process.env" in line:
                continue

            match = self.KEY_ASSIGN_PATTERN.search(line)
            if match:
                token_val = match.group(1)
                if not _is_placeholder(token_val):
                    redacted_evidence = BaseScanner.redact_evidence(line.strip())
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line=idx,
                            evidence=redacted_evidence,
                        )
                    )
        return findings


class HardcodedPasswordRule(BaseCustomRule):
    """Detects hardcoded passwords assigned to configuration or credential variables."""

    rule_id: str = "custom.secrets.hardcoded-password"
    title: str = "Hardcoded Password in Source Code"
    description: str = (
        "A cleartext password appears to be hardcoded in application code. "
        "Use external environment variables or a key vault instead of static values."
    )
    domain: str = "Secrets & Sensitive Information Management"
    canonical_domain: CanonicalDomainType = "secrets"
    severity: SeverityType = "high"
    confidence: ConfidenceType = "medium"
    file_extensions: tuple[str, ...] = (".py", ".js", ".ts", ".env")
    cwe_id: int = 259

    PASSWORD_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)(?:^|[\s,;{(])(?:password|passwd|db_password|admin_password)\s*[:=]\s*['"]([^'"]{8,128})['"]"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if "os.getenv" in line or "os.environ" in line or "process.env" in line:
                continue

            match = self.PASSWORD_PATTERN.search(line)
            if match:
                pwd_val = match.group(1)
                if not _is_placeholder(pwd_val):
                    redacted_evidence = BaseScanner.redact_evidence(line.strip())
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line=idx,
                            evidence=redacted_evidence,
                        )
                    )
        return findings


class PrivateKeyMaterialRule(BaseCustomRule):
    """Detects cleartext private cryptographic key blocks embedded in source or config."""

    rule_id: str = "custom.secrets.private-key-material"
    title: str = "Private Cryptographic Key Material"
    description: str = (
        "An unencrypted private cryptographic key block is embedded in source code or configuration. "
        "Private keys must never be committed to source control."
    )
    domain: str = "Secrets & Sensitive Information Management"
    canonical_domain: CanonicalDomainType = "secrets"
    severity: SeverityType = "critical"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (
        ".py",
        ".js",
        ".ts",
        ".env",
        ".json",
        ".yaml",
        ".yml",
        ".pem",
        ".key",
    )
    cwe_id: int = 312

    KEY_HEADER_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if self.KEY_HEADER_PATTERN.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence="[REDACTED_PRIVATE_KEY_HEADER]",
                    )
                )
        return findings
