"""
Custom web security rule detecting path traversal via dynamic file opens.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class PathTraversalOpenRule(BaseCustomRule):
    """Detects file open sinks with dynamic user-controlled path concatenations."""

    rule_id: str = "custom.web.path-traversal-open"
    title: str = "Potential Path Traversal in File Open"
    description: str = (
        "Opening files using dynamic string interpolation without path sanitization (e.g. os.path.basename) "
        "may allow attackers to access arbitrary files on the filesystem via directory traversal sequences (../)."
    )
    domain: str = "Web Application Security"
    canonical_domain: CanonicalDomainType = "input_validation"
    severity: SeverityType = "high"
    confidence: ConfidenceType = "medium"
    file_extensions: tuple[str, ...] = (".py", ".js", ".ts")
    cwe_id: int = 22

    OPEN_DYNAMIC_PY: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)\bopen\s*\(\s*(?:f['"][^'"]*\{[a-zA-Z0-9_\.]+\}[^'"]*['"]|[a-zA-Z0-9_]+\s*\+\s*['"][^'"]*['"]|['"][^'"]*['"]\s*\+\s*[a-zA-Z0-9_]+)"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if "os.path.basename" in line or "Path(" in line or "secure_filename" in line:
                continue

            if self.OPEN_DYNAMIC_PY.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=line.strip(),
                    )
                )
        return findings
