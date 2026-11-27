"""
False positive management, deduplication, and suppression engine for Thread Trace.

Provides deterministic finding deduplication across overlapping scanner outputs,
traceable allowlisting by rule ID or file globs, and critical severity guardrails.
"""

import fnmatch
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.finding import Finding

TOOL_PRIORITY: dict[str, int] = {
    "gitleaks": 10,
    "bandit": 9,
    "osv-scanner": 8,
    "semgrep": 7,
    "custom-rules": 5,
    "unknown": 1,
}


class SuppressionRule(BaseModel):
    """Configuration rule for suppressing known false positives or test findings."""

    rule_id: str | None = Field(
        default=None,
        description="Exact rule ID to suppress (e.g., 'bandit.B101'). If None, matches all rules.",
    )
    file_pattern: str | None = Field(
        default=None,
        description="Glob pattern for paths to suppress (e.g., 'tests/**', 'fixtures/**').",
    )
    reason: str = Field(
        ...,
        min_length=1,
        description="Mandatory justification for the suppression decision for auditability.",
    )
    allow_critical: bool = Field(
        default=False,
        description="Must be explicitly True to permit suppression of critical severity findings.",
    )


def deduplicate_findings(
    findings: list[Finding],
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """
    Deduplicate overlapping findings produced by multiple scanners on the same target.

    Grouping Key:
    - For line-level findings: (file, line, domain)
    - For manifest/file-level findings (line is None): (file, rule_id)

    Precedence is resolved via TOOL_PRIORITY, preserving the authoritative finding
    while recording the duplicate in the suppression audit trail.

    Args:
        findings: List of normalized Finding instances.

    Returns:
        tuple[list[Finding], list[dict[str, Any]]]:
            - Deduplicated active findings.
            - Audit records of suppressed duplicate findings.
    """
    grouped: dict[tuple[str, Any, str], list[Finding]] = {}

    for f in findings:
        if f.line is not None:
            key = (f.file, f.line, f.domain)
        else:
            key = (f.file, f.line, f.rule_id)

        if key not in grouped:
            grouped[key] = []
        grouped[key].append(f)

    active_findings: list[Finding] = []
    suppression_log: list[dict[str, Any]] = []

    for key, group in grouped.items():
        if len(group) == 1:
            active_findings.append(group[0])
            continue

        # Sort group by tool priority descending (highest priority tool first)
        sorted_group = sorted(
            group,
            key=lambda x: TOOL_PRIORITY.get(x.tool.lower(), 1),
            reverse=True,
        )

        authoritative = sorted_group[0]
        active_findings.append(authoritative)

        # Record duplicates in audit trail
        for dup in sorted_group[1:]:
            suppression_log.append(
                {
                    "suppressed_finding_id": dup.id,
                    "rule_id": dup.rule_id,
                    "tool": dup.tool,
                    "file": dup.file,
                    "line": dup.line,
                    "reason": f"Duplicate of authoritative finding '{authoritative.id}' ({authoritative.tool})",
                    "authoritative_finding_id": authoritative.id,
                }
            )

    return active_findings, suppression_log


def apply_suppressions(
    findings: list[Finding],
    suppression_rules: list[SuppressionRule],
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """
    Apply configured suppression rules to filter out accepted risks or false positives.

    Enforces critical severity guardrails: critical vulnerabilities are never suppressed
    unless the suppression rule explicitly specifies allow_critical=True.

    Args:
        findings: List of Finding instances.
        suppression_rules: List of active SuppressionRule configurations.

    Returns:
        tuple[list[Finding], list[dict[str, Any]]]:
            - Active unsuppressed findings.
            - Audit records of suppressed findings.
    """
    if not suppression_rules:
        return findings, []

    active: list[Finding] = []
    suppressed_log: list[dict[str, Any]] = []

    for f in findings:
        suppressed_by_rule: SuppressionRule | None = None

        for rule in suppression_rules:
            # Check rule_id match
            if rule.rule_id and rule.rule_id != f.rule_id:
                continue

            # Check file pattern match
            if rule.file_pattern:
                norm_file = f.file.replace("\\", "/")
                pattern = rule.file_pattern.replace("\\", "/")
                if not (fnmatch.fnmatch(norm_file, pattern) or fnmatch.fnmatch(norm_file, f"*/{pattern}")):
                    continue

            # Guardrail: Critical findings cannot be suppressed without allow_critical=True
            if f.severity == "critical" and not rule.allow_critical:
                continue

            suppressed_by_rule = rule
            break

        if suppressed_by_rule:
            suppressed_log.append(
                {
                    "suppressed_finding_id": f.id,
                    "rule_id": f.rule_id,
                    "tool": f.tool,
                    "file": f.file,
                    "line": f.line,
                    "severity": f.severity,
                    "reason": suppressed_by_rule.reason,
                    "matched_pattern": suppressed_by_rule.file_pattern,
                }
            )
        else:
            active.append(f)

    return active, suppressed_log
