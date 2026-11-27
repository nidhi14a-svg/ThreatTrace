"""
Custom web security rule detecting command injection via shell execution sinks.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class CommandInjectionShellRule(BaseCustomRule):
    """Detects command execution with shell=True or formatted strings in os.system()."""

    rule_id: str = "custom.web.command-injection-shell"
    title: str = "Command Execution with Shell Enabled"
    description: str = (
        "Invoking system commands with shell=True or via os.system with dynamic arguments "
        "enables arbitrary OS command injection. Pass command arguments as a list with shell=False."
    )
    domain: str = "Web Application Security"
    canonical_domain: CanonicalDomainType = "injection"
    severity: SeverityType = "high"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py",)
    cwe_id: int = 78

    SUBPROCESS_SHELL_TRUE: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)subprocess\.(?:Popen|call|check_call|check_output|run)\s*\([^)]*shell\s*=\s*True"""
    )
    OS_SYSTEM_DYNAMIC: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)os\.(?:system|popen)\s*\(\s*(?:f['"][^'"]*\{|['"][^'"]*%\s*|[a-zA-Z0-9_]+\s*\+)"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if self.SUBPROCESS_SHELL_TRUE.search(line) or self.OS_SYSTEM_DYNAMIC.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=line.strip(),
                    )
                )
        return findings
