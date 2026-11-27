"""
Custom web security rule detecting SQL injection via dynamic string formatting.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class SqlInjectionFStringRule(BaseCustomRule):
    """Detects SQL queries constructed via f-strings or string formatting inside execute()."""

    rule_id: str = "custom.web.sql-injection-fstring"
    title: str = "SQL Query Constructed via String Formatting"
    description: str = (
        "Detected SQL query built using string formatting or f-strings inside an execution sink. "
        "Use parameterized queries (e.g., execute('SELECT * FROM users WHERE id = %s', (user_id,))) "
        "to prevent SQL injection."
    )
    domain: str = "Web Application Security"
    canonical_domain: CanonicalDomainType = "injection"
    severity: SeverityType = "high"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py",)
    cwe_id: int = 89

    SQL_EXEC_FSTRING: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)\.(?:execute|executemany)\s*\(\s*f['"][^'"]*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+[^'"]*?\{[a-zA-Z0-9_\.]+\}"""
    )
    SQL_EXEC_PERCENT: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)\.(?:execute|executemany)\s*\(\s*['"][^'"]*?(?:SELECT|INSERT|UPDATE|DELETE)\s+[^'"]*?%s['"]\s*%\s*(?:\([^\)]+\)|[a-zA-Z0-9_]+)"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if self.SQL_EXEC_FSTRING.search(line) or self.SQL_EXEC_PERCENT.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=line.strip(),
                    )
                )
        return findings
