"""
Base custom rule interface for Thread Trace.

Provides the abstract definition for all project-specific security rules,
ensuring consistent metadata, typing, and execution contracts.
"""

from abc import ABC, abstractmethod
from typing import Any, Literal

SeverityType = Literal["critical", "high", "medium", "low"]
ConfidenceType = Literal["high", "medium", "low"]
CanonicalDomainType = Literal[
    "injection",
    "authentication",
    "authorization",
    "cryptography",
    "secrets",
    "dependencies",
    "configuration",
    "input_validation",
    "logging",
    "other",
]


class BaseCustomRule(ABC):
    """
    Abstract base class for all Thread Trace custom security detection rules.

    Every custom rule must:
    1. Define a unique rule_id starting with 'custom.'.
    2. Provide standardized severity, confidence, and canonical domain metadata.
    3. Restrict analysis to appropriate file extensions.
    4. Implement evaluate() returning standardized raw finding dictionaries.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier (e.g., 'custom.web.sql-injection-fstring')."""
        raise NotImplementedError

    @property
    @abstractmethod
    def title(self) -> str:
        """Concise, human-readable vulnerability title."""
        raise NotImplementedError

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed technical summary of the security risk."""
        raise NotImplementedError

    @property
    @abstractmethod
    def domain(self) -> str:
        """Canonical project-level display domain (e.g., 'Web Application Security')."""
        raise NotImplementedError

    @property
    @abstractmethod
    def canonical_domain(self) -> CanonicalDomainType:
        """Strict backend domain identifier (e.g., 'injection', 'secrets', 'authentication')."""
        raise NotImplementedError

    @property
    @abstractmethod
    def severity(self) -> SeverityType:
        """Normalized severity tier: critical, high, medium, or low."""
        raise NotImplementedError

    @property
    @abstractmethod
    def confidence(self) -> ConfidenceType:
        """Detection confidence tier: high, medium, or low."""
        raise NotImplementedError

    @property
    @abstractmethod
    def file_extensions(self) -> tuple[str, ...]:
        """Tuple of supported lowercase file extensions (e.g., ('.py', '.js', '.ts'))."""
        raise NotImplementedError

    @property
    def cwe_id(self) -> int | None:
        """Optional Common Weakness Enumeration identifier (e.g., 89 for SQLi)."""
        return None

    @property
    def raw_category(self) -> str:
        """Default raw category derived from canonical domain."""
        return self.canonical_domain

    @abstractmethod
    def evaluate(
        self,
        file_path: str,
        content: str,
        lines: list[str],
    ) -> list[dict[str, Any]]:
        """
        Evaluate file content for security vulnerabilities.

        Args:
            file_path: Workspace-relative POSIX path to the target file.
            content: Entire text content of the file.
            lines: List of individual lines in the file.

        Returns:
            list[dict[str, Any]]: List of raw finding dictionaries.
        """
        raise NotImplementedError

    def create_finding(
        self,
        file_path: str,
        line: int | None,
        evidence: str,
        title: str | None = None,
        severity: SeverityType | None = None,
        confidence: ConfidenceType | None = None,
        raw_category: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Helper method to construct a standard raw finding dictionary from this rule.
        """
        finding: dict[str, Any] = {
            "scanner_name": "custom-rules",
            "rule_id": self.rule_id,
            "title": title or self.title,
            "severity": severity or self.severity,
            "file": file_path,
            "line": line,
            "evidence": evidence,
            "confidence": confidence or self.confidence,
            "domain": self.domain,
            "canonical_domain": self.canonical_domain,
            "raw_category": raw_category or self.raw_category,
            "description": self.description,
            "cwe_id": self.cwe_id,
        }
        if extra:
            finding.update(extra)
        return finding
