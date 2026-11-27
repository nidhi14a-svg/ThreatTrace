"""Tests verifying false-positive rates, deduplication, and suppression.

Validates:
- Representative clean projects yield zero false positives
- Cross-scanner finding deduplication priority
- Traceable allowlisting and suppression filtering
- Critical severity guardrail against silent suppression
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.scanners.custom_rules import default_registry, register_all_custom_rules
from app.scanners.custom_rules.scanner import CustomRulesScanner
from app.scanners.normalizer import normalize_scanner_result
from app.scanners.suppression import (
    SuppressionRule,
    apply_suppressions,
    deduplicate_findings,
)
from app.schemas.finding import Finding

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
CLEAN_DIR = FIXTURES_DIR / "clean"


@pytest.fixture(scope="module", autouse=True)
def setup_rules():
    """Ensure all modular custom rules are registered."""
    register_all_custom_rules(default_registry)


@pytest.mark.anyio
async def test_clean_fixtures_yield_zero_false_positives() -> None:
    """Verify representative clean projects trigger ZERO findings across all domains."""
    scanner = CustomRulesScanner(registry=default_registry)
    result = await scanner.scan(str(CLEAN_DIR))

    assert result.status == "success"
    assert result.error is None
    assert len(result.findings) == 0, (
        f"Clean fixtures triggered false positives: {[f.get('rule_id') for f in result.findings]}"
    )


def test_cross_tool_finding_deduplication_prefers_authoritative_tool() -> None:
    """Verify identical findings from overlapping tools are deduplicated to higher priority tool."""
    f_semgrep = Finding(
        id="f-semgrep-1",
        domain="Web Application Security",
        rule_id="semgrep.py.sql-injection",
        title="SQL Injection via string formatting",
        severity="high",
        file="app/views.py",
        line=42,
        evidence="query = f'SELECT * FROM users'",
        confidence="high",
        tool="semgrep",
    )

    f_custom = Finding(
        id="f-custom-1",
        domain="Web Application Security",
        rule_id="custom.web.sql-injection-fstring",
        title="SQL Injection via f-string",
        severity="high",
        file="app/views.py",
        line=42,
        evidence="query = f'SELECT * FROM users'",
        confidence="high",
        tool="custom-rules",
    )

    active, dupes = deduplicate_findings([f_custom, f_semgrep])

    assert len(active) == 1
    assert len(dupes) == 1
    # Semgrep (priority 7) takes precedence over custom-rules (priority 5)
    assert active[0].tool == "semgrep"
    assert dupes[0]["suppressed_finding_id"] == "f-custom-1"


def test_critical_severity_guardrail_prevents_silent_suppression() -> None:
    """Verify critical severity findings are not suppressed without explicit approval."""
    f_critical = Finding(
        id="f-crit-1",
        domain="Web Application Security",
        rule_id="custom.web.command-injection-shell",
        title="Remote Command Injection",
        severity="critical",
        file="src/utils.py",
        line=10,
        evidence="subprocess.Popen(cmd, shell=True)",
        confidence="high",
        tool="custom-rules",
    )

    # Standard suppression rule without allow_critical
    rule = SuppressionRule(
        file_pattern="src/**",
        reason="Test pattern suppression",
        allow_critical=False,
    )

    active, suppressed = apply_suppressions([f_critical], [rule])
    assert len(active) == 1
    assert len(suppressed) == 0

    # Explicit audit approval rule with allow_critical=True
    audit_rule = SuppressionRule(
        file_pattern="src/**",
        reason="Approved architectural exception per SEC-104",
        allow_critical=True,
    )

    active2, suppressed2 = apply_suppressions([f_critical], [audit_rule])
    assert len(active2) == 0
    assert len(suppressed2) == 1
    assert suppressed2[0]["suppressed_finding_id"] == "f-crit-1"
