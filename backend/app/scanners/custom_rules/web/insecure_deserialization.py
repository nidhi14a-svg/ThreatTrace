"""
Custom web security rules detecting insecure deserialization and dynamic code evaluation.
"""

import re
from typing import Any, ClassVar

from app.scanners.custom_rules.base_rule import (
    BaseCustomRule,
    CanonicalDomainType,
    ConfidenceType,
    SeverityType,
)


class InsecurePickleLoadRule(BaseCustomRule):
    """Detects unsafe object deserialization via pickle.loads or unanchored yaml.load."""

    rule_id: str = "custom.web.insecure-pickle-load"
    title: str = "Insecure Object Deserialization"
    description: str = (
        "Deserializing untrusted data with pickle.loads() or unsafe yaml.load() allows attackers "
        "to execute arbitrary Python code via crafted payloads. Use safe serializers like json or yaml.safe_load()."
    )
    domain: str = "Web Application Security"
    canonical_domain: CanonicalDomainType = "input_validation"
    severity: SeverityType = "critical"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py",)
    cwe_id: int = 502

    PICKLE_LOAD_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)(?:pickle|_pickle|cPickle)\.(?:loads|load)\s*\("""
    )
    YAML_UNSAFE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)yaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader)"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if self.PICKLE_LOAD_PATTERN.search(line) or self.YAML_UNSAFE_PATTERN.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=line.strip(),
                    )
                )
        return findings


class UnsafeEvalExecRule(BaseCustomRule):
    """Detects dynamic code execution sinks with non-constant inputs."""

    rule_id: str = "custom.web.unsafe-eval-exec"
    title: str = "Dynamic Code Execution Sink"
    description: str = (
        "Direct execution of dynamic strings via eval() or exec() allows remote code execution. "
        "Avoid dynamic evaluation of user-controlled code."
    )
    domain: str = "Web Application Security"
    canonical_domain: CanonicalDomainType = "injection"
    severity: SeverityType = "critical"
    confidence: ConfidenceType = "high"
    file_extensions: tuple[str, ...] = (".py", ".js", ".ts")
    cwe_id: int = 95

    EVAL_EXEC_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?i)\b(?:eval|exec)\s*\(\s*(?!['"][^'"]*['"]\s*\))([a-zA-Z0-9_\.]+)"""
    )

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            # Exclude standard safe comments or tests
            if line.strip().startswith(("#", "//", "/*")):
                continue

            if self.EVAL_EXEC_PATTERN.search(line):
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=line.strip(),
                    )
                )
        return findings
