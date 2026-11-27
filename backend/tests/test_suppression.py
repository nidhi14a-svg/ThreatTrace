import pytest

from app.scanners.suppression import (
    SuppressionRule,
    apply_suppressions,
    deduplicate_findings,
)
from app.schemas.finding import Finding


def create_test_finding(
    fid: str,
    tool: str,
    rule_id: str,
    file: str,
    line: int | None,
    severity: str = "high",
    domain: str = "Web Application Security",
) -> Finding:
    return Finding(
        id=fid,
        tool=tool,
        rule_id=rule_id,
        title="Test Finding",
        severity=severity,  # type: ignore
        file=file,
        line=line,
        evidence="code snippet",
        confidence="high",
        domain=domain,
    )


# ============================================================================
# 1. Deduplication Tests
# ============================================================================


def test_deduplicate_findings_prefers_higher_priority_tool():
    """Verify deduplication keeps the authoritative tool and logs the duplicate."""
    # Bandit (priority 9) and Custom Rules (priority 5) on same file and line
    f_custom = create_test_finding("f1", "custom-rules", "custom.web.sql", "app.py", 42)
    f_bandit = create_test_finding("f2", "bandit", "bandit.B608", "app.py", 42)

    active, audit_log = deduplicate_findings([f_custom, f_bandit])

    assert len(active) == 1
    assert active[0].id == "f2"
    assert active[0].tool == "bandit"

    assert len(audit_log) == 1
    assert audit_log[0]["suppressed_finding_id"] == "f1"
    assert "Duplicate of authoritative finding 'f2'" in audit_log[0]["reason"]


def test_deduplicate_findings_preserves_distinct_findings():
    """Verify findings on different lines or files are not deduplicated."""
    f1 = create_test_finding("f1", "semgrep", "rule1", "app.py", 10)
    f2 = create_test_finding("f2", "bandit", "rule2", "app.py", 20)
    f3 = create_test_finding("f3", "gitleaks", "rule3", "other.py", 10)

    active, audit_log = deduplicate_findings([f1, f2, f3])

    assert len(active) == 3
    assert len(audit_log) == 0


# ============================================================================
# 2. Suppression and Allowlist Tests
# ============================================================================


def test_apply_suppressions_by_rule_id():
    """Verify suppression by rule ID filters matching findings and records audit log."""
    f1 = create_test_finding("f1", "bandit", "bandit.B101", "app.py", 10, severity="low")
    f2 = create_test_finding("f2", "bandit", "bandit.B608", "app.py", 20, severity="high")

    rules = [
        SuppressionRule(
            rule_id="bandit.B101",
            reason="Assert statements acceptable in internal services",
        )
    ]

    active, audit_log = apply_suppressions([f1, f2], rules)

    assert len(active) == 1
    assert active[0].id == "f2"
    assert len(audit_log) == 1
    assert audit_log[0]["suppressed_finding_id"] == "f1"
    assert audit_log[0]["reason"] == "Assert statements acceptable in internal services"


def test_apply_suppressions_by_file_pattern():
    """Verify suppression by glob pattern filters matching files."""
    f_test = create_test_finding("f1", "bandit", "bandit.B105", "tests/unit/test_auth.py", 15)
    f_prod = create_test_finding("f2", "bandit", "bandit.B105", "app/auth.py", 15)

    rules = [
        SuppressionRule(
            file_pattern="tests/**",
            reason="Test mock credentials ignored",
        )
    ]

    active, audit_log = apply_suppressions([f_test, f_prod], rules)

    assert len(active) == 1
    assert active[0].id == "f2"
    assert len(audit_log) == 1
    assert audit_log[0]["suppressed_finding_id"] == "f1"


def test_critical_severity_guardrail_prevents_silent_suppression():
    """Verify critical findings cannot be suppressed without allow_critical=True."""
    f_critical = create_test_finding(
        "f_crit",
        "gitleaks",
        "gitleaks.aws-key",
        "tests/mock_key.py",
        1,
        severity="critical",
    )

    # Rule without allow_critical=True
    rules = [
        SuppressionRule(
            file_pattern="tests/**",
            reason="Try to suppress tests",
            allow_critical=False,
        )
    ]

    active, audit_log = apply_suppressions([f_critical], rules)

    # Critical finding was NOT suppressed!
    assert len(active) == 1
    assert active[0].id == "f_crit"
    assert len(audit_log) == 0


def test_critical_severity_suppression_allowed_when_explicit():
    """Verify critical findings can be suppressed when allow_critical=True is set."""
    f_critical = create_test_finding(
        "f_crit",
        "gitleaks",
        "gitleaks.aws-key",
        "tests/mock_key.py",
        1,
        severity="critical",
    )

    rules = [
        SuppressionRule(
            file_pattern="tests/**",
            reason="Explicit test fixture exemption signed off by security team",
            allow_critical=True,
        )
    ]

    active, audit_log = apply_suppressions([f_critical], rules)

    assert len(active) == 0
    assert len(audit_log) == 1
    assert audit_log[0]["suppressed_finding_id"] == "f_crit"
