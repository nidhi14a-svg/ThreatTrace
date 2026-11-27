"""
Custom configuration rule detecting unpinned wildcard dependencies in package manifests.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class UnpinnedDependenciesRule(BaseCustomRule):
    """Detects wildcard '*' version specifications in requirements.txt or package.json."""

    rule_id: str = "custom.config.unpinned-dependency"
    title: str = "Unpinned Wildcard Dependency"
    description: str = (
        "Dependencies declared with wildcard ('*') versions allow automatic upgrades to breaking "
        "or potentially compromised package versions. Pin dependencies to exact versions."
    )
    domain: str = "Dependency & Configuration Security"
    canonical_domain: CanonicalDomainType = "dependencies"
    severity: SeverityType = "medium"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".txt", ".json")
    cwe_id: int = 1104

    PIP_WILDCARD: ClassVar[re.Pattern[str]] = re.compile(
        r"""^[a-zA-Z0-9_\-\.]+\s*==\s*\*"""
    )
    NPM_WILDCARD: ClassVar[re.Pattern[str]] = re.compile(
        r'''"[a-zA-Z0-9_\-\.\/]+"\s*:\s*"\*"'''
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        lower_file = file_path.lower()
        if not (lower_file.endswith(".txt") or lower_file.endswith("package.json")):
            return []

        findings = []
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if self.PIP_WILDCARD.match(stripped) or self.NPM_WILDCARD.search(stripped):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=stripped,
                    )
                )
        return findings
