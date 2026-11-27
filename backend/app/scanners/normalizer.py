"""
Finding normalization engine for Thread Trace.

Transforms raw finding dictionaries emitted by disparate scanners (Semgrep, Bandit,
Gitleaks, OSV-Scanner, Custom Rules) into the canonical Finding Pydantic schema.
"""

import uuid
from typing import Any, Literal

from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult
from app.schemas.finding import Finding

SeverityType = Literal["critical", "high", "medium", "low"]

SEVERITY_MAP: dict[str, SeverityType] = {
    "critical": "critical",
    "high": "high",
    "error": "high",
    "medium": "medium",
    "warning": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "low",
}

CONFIDENCE_MAP: dict[str, str] = {
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def normalize_raw_finding(
    raw: dict[str, Any],
    default_tool: str = "unknown",
) -> Finding:
    """
    Normalize a single raw scanner finding dictionary into a canonical Finding model.

    Enforces coordinate standardization, path normalization, evidence bounding,
    in-memory credential redaction, and original category preservation.

    Args:
        raw: Raw finding dictionary from ScannerExecutionResult.findings.
        default_tool: Fallback tool identifier if missing from raw finding.

    Returns:
        Finding: Validated canonical finding instance.
    """
    fid = str(raw.get("id") or raw.get("finding_id") or f"find_{uuid.uuid4().hex[:12]}")

    # Tool mapping
    tool_name = str(raw.get("tool") or raw.get("scanner_name") or default_tool)

    # Rule ID mapping
    rule_id = str(
        raw.get("rule_id")
        or raw.get("check_id")
        or raw.get("test_id")
        or "rule_unknown"
    )

    # Domain mapping
    domain = str(raw.get("domain") or raw.get("canonical_domain") or "General Security")

    # Title mapping
    title = str(
        raw.get("title")
        or raw.get("message")
        or raw.get("issue_text")
        or rule_id
    )[:200]

    # Severity normalization
    raw_sev = str(raw.get("severity") or raw.get("issue_severity") or "medium").strip().lower()
    norm_sev: SeverityType = SEVERITY_MAP.get(raw_sev, "medium")

    # Confidence normalization
    raw_conf = str(raw.get("confidence") or raw.get("issue_confidence") or "medium").strip().lower()
    norm_conf = CONFIDENCE_MAP.get(raw_conf, "medium")

    # File path normalization
    raw_file = str(raw.get("file") or raw.get("filename") or raw.get("path") or "[UNKNOWN_FILE]")
    norm_file = raw_file.replace("\\", "/").lstrip("./")

    # Line number normalization
    line_val = raw.get("line") or raw.get("line_number")
    norm_line: int | None = None
    if isinstance(line_val, int) and line_val >= 1:
        norm_line = line_val
    elif isinstance(line_val, str) and line_val.isdigit():
        parsed = int(line_val)
        if parsed >= 1:
            norm_line = parsed

    # Evidence bounding and mandatory redaction
    raw_evidence = str(raw.get("evidence") or raw.get("code") or raw.get("match") or "")
    redacted_evidence = BaseScanner.redact_evidence(raw_evidence)
    bounded_evidence = BaseScanner.bound_evidence(redacted_evidence, max_chars=1000)

    # Raw category preservation
    raw_category = (
        raw.get("raw_category")
        or raw.get("category")
        or raw.get("test_name")
        or None
    )
    if raw_category is not None:
        raw_category = str(raw_category)

    return Finding(
        id=fid,
        domain=domain,
        rule_id=rule_id,
        title=title,
        severity=norm_sev,
        file=norm_file,
        line=norm_line,
        evidence=bounded_evidence,
        confidence=norm_conf,
        explanation=raw.get("explanation"),
        recommendation=raw.get("recommendation"),
        tool=tool_name,
        raw_category=raw_category,
    )


def normalize_scanner_result(result: ScannerExecutionResult) -> list[Finding]:
    """
    Normalize all raw findings in a ScannerExecutionResult.

    Args:
        result: ScannerExecutionResult returned by any scanner adapter.

    Returns:
        list[Finding]: List of canonical Finding instances.
    """
    return [
        normalize_raw_finding(raw_f, default_tool=result.scanner_name)
        for raw_f in result.findings
    ]
