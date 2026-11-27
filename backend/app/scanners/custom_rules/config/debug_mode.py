"""
Custom configuration security rule detecting enabled debug mode.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class DebugModeEnabledRule(BaseCustomRule):
    """Detects DEBUG = True or debug=True flags in application settings."""

    rule_id: str = "custom.config.debug-mode-enabled"
    title: str = "Debug Mode Enabled in Configuration"
    description: str = (
        "Application debug mode is explicitly enabled. In production environments, debug mode "
        "leaks interactive debuggers, stack traces, and internal variables to untrusted users."
    )
    domain: str = "Dependency & Configuration Security"
    canonical_domain: CanonicalDomainType = "configuration"
    severity: SeverityType = "high"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py", ".env", ".json", ".yaml", ".yml")
    cwe_id: int = 489

    DEBUG_TRUE_PY: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)(?:^|[\s,;{(])DEBUG\s*=\s*True|(?:\.run\([^)]*debug\s*=\s*True)"""
    )
    DEBUG_TRUE_ENV: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)^DEBUG\s*=\s*(?:true|1)\b"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        # Skip obvious test files
        lower_path = file_path.lower()
        if "test" in lower_path or "conftest" in lower_path:
            return []

        findings = []
        for idx, line in enumerate(lines, start=1):
            if "os.getenv" in line or "os.environ" in line:
                continue

            if self.DEBUG_TRUE_PY.search(line) or self.DEBUG_TRUE_ENV.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=line.strip(),
                    )
                )
        return findings
