import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.scanners.bandit_scanner import BanditScanner
from app.scanners.base_scanner import (
    BaseScanner,
    ScannerExecutionResult,
    aggregate_scanner_statuses,
)
from app.scanners.dependency_scanner import DependencyScanner
from app.scanners.secrets_scanner import SecretsScanner
from app.scanners.semgrep_scanner import SemgrepScanner


# ============================================================================
# 1. safe_scan Exception Confinement & Fault Isolation
# ============================================================================


class CrashingScanner(BaseScanner):
    name: str = "crasher"

    async def scan(self, workspace: str) -> ScannerExecutionResult:
        raise RuntimeError("Simulated internal kernel panic or unexpected crash")


class SuccessfulScanner(BaseScanner):
    name: str = "winner"

    async def scan(self, workspace: str) -> ScannerExecutionResult:
        return self.create_result(
            status="success",
            findings=[{"scanner_name": self.name, "rule_id": "test.rule", "title": "Test Finding"}],
            duration_seconds=0.12,
        )


@pytest.mark.anyio
async def test_safe_scan_delegates_to_scan_on_success():
    """Verify safe_scan returns normal result when scan() succeeds."""
    scanner = SuccessfulScanner()
    result = await scanner.safe_scan("/workspace")

    assert isinstance(result, ScannerExecutionResult)
    assert result.status == "success"
    assert result.scanner_name == "winner"
    assert len(result.findings) == 1
    assert result.error is None
    assert result.is_successful is True
    assert result.has_findings is True


@pytest.mark.anyio
async def test_safe_scan_traps_unhandled_exception_and_returns_failed():
    """Verify safe_scan intercepts unhandled Python exceptions, returning status='failed'."""
    scanner = CrashingScanner()
    result = await scanner.safe_scan("/workspace")

    assert isinstance(result, ScannerExecutionResult)
    assert result.status == "failed"
    assert result.scanner_name == "crasher"
    assert result.findings == []
    assert "Unexpected scanner exception in crasher" in result.error
    assert "Simulated internal kernel panic" in result.error
    assert result.is_successful is False
    assert result.has_findings is False


# ============================================================================
# 2. ScannerExecutionResult Helper Properties
# ============================================================================


def test_scanner_execution_result_properties():
    """Verify is_successful and has_findings helper properties."""
    r_success = ScannerExecutionResult(
        scanner_name="tool",
        status="success",
        findings=[{"id": "1"}],
        duration_seconds=0.5,
    )
    assert r_success.is_successful is True
    assert r_success.has_findings is True

    r_partial = ScannerExecutionResult(
        scanner_name="tool",
        status="partial",
        findings=[{"id": "2"}],
        duration_seconds=0.5,
        error="Warning on 1 file",
    )
    assert r_partial.is_successful is True
    assert r_partial.has_findings is True

    r_failed = ScannerExecutionResult(
        scanner_name="tool",
        status="failed",
        findings=[],
        duration_seconds=0.0,
        error="Fatal error",
    )
    assert r_failed.is_successful is False
    assert r_failed.has_findings is False

    r_skipped = ScannerExecutionResult(
        scanner_name="tool",
        status="skipped",
        findings=[],
        duration_seconds=0.0,
    )
    assert r_skipped.is_successful is False
    assert r_skipped.has_findings is False


# ============================================================================
# 3. Status Aggregation Matrix Verification
# ============================================================================


def test_aggregate_scanner_statuses_empty_list():
    """Verify empty scanner list yields 'skipped'."""
    assert aggregate_scanner_statuses([]) == "skipped"


def test_aggregate_scanner_statuses_all_skipped():
    """Verify all skipped results yield 'skipped'."""
    results = [
        ScannerExecutionResult(scanner_name="a", status="skipped"),
        ScannerExecutionResult(scanner_name="b", status="skipped"),
    ]
    assert aggregate_scanner_statuses(results) == "skipped"


def test_aggregate_scanner_statuses_all_failed():
    """Verify all failed results yield 'failed'."""
    results = [
        ScannerExecutionResult(scanner_name="a", status="failed", error="timeout"),
        ScannerExecutionResult(scanner_name="b", status="failed", error="crash"),
    ]
    assert aggregate_scanner_statuses(results) == "failed"


def test_aggregate_scanner_statuses_all_success():
    """Verify all successful results yield 'success'."""
    results = [
        ScannerExecutionResult(scanner_name="a", status="success", findings=[{"x": 1}]),
        ScannerExecutionResult(scanner_name="b", status="success", findings=[]),
    ]
    assert aggregate_scanner_statuses(results) == "success"


def test_aggregate_scanner_statuses_mixed_success_and_skipped():
    """Verify mixed success and skipped yields 'success' (unsupported tools do not degrade)."""
    results = [
        ScannerExecutionResult(scanner_name="semgrep", status="success", findings=[{"x": 1}]),
        ScannerExecutionResult(scanner_name="bandit", status="skipped"),  # No Python files
    ]
    assert aggregate_scanner_statuses(results) == "success"


def test_aggregate_scanner_statuses_mixed_success_and_failed():
    """Verify mixed success and failed yields 'partial' (findings preserved)."""
    results = [
        ScannerExecutionResult(scanner_name="semgrep", status="success", findings=[{"x": 1}]),
        ScannerExecutionResult(scanner_name="bandit", status="failed", error="Syntax crash"),
    ]
    assert aggregate_scanner_statuses(results) == "partial"


def test_aggregate_scanner_statuses_mixed_partial_and_success():
    """Verify partial and success yields 'partial'."""
    results = [
        ScannerExecutionResult(scanner_name="semgrep", status="success", findings=[{"x": 1}]),
        ScannerExecutionResult(scanner_name="bandit", status="partial", findings=[{"y": 2}]),
    ]
    assert aggregate_scanner_statuses(results) == "partial"


# ============================================================================
# 4. End-to-End Fault Isolation Across Multiple Concurrent Scanners
# ============================================================================


@pytest.mark.anyio
async def test_concurrent_fault_isolation_failure_does_not_abort_peers():
    """
    Verify concurrent execution of 4 scanners where one crashes:
    1. Semgrep succeeds with 2 findings.
    2. Bandit crashes with unhandled exception (caught by safe_scan).
    3. Secrets succeeds with 1 finding.
    4. Dependency is skipped (0 manifests).

    Outcome:
    - All 4 results are returned.
    - Findings from Semgrep (2) and Secrets (1) are 100% intact.
    - Aggregate status is 'partial' (not failed).
    """
    s_semgrep = SuccessfulScanner()
    s_semgrep.name = "semgrep"

    s_bandit = CrashingScanner()
    s_bandit.name = "bandit"

    s_secrets = SuccessfulScanner()
    s_secrets.name = "secrets"

    s_dep = DependencyScanner()

    # Mock dependency scanner skipping because no workspace exists
    async def mock_dep_scan(ws):
        return s_dep.create_result(status="skipped", findings=[], error=None)

    s_dep.scan = mock_dep_scan

    # Run concurrently via safe_scan
    results = await asyncio.gather(
        s_semgrep.safe_scan("/workspace"),
        s_bandit.safe_scan("/workspace"),
        s_secrets.safe_scan("/workspace"),
        s_dep.safe_scan("/workspace"),
    )

    assert len(results) == 4

    r_semgrep, r_bandit, r_secrets, r_dep = results

    # Semgrep check
    assert r_semgrep.scanner_name == "semgrep"
    assert r_semgrep.status == "success"
    assert len(r_semgrep.findings) == 1

    # Bandit check (crashed safely)
    assert r_bandit.scanner_name == "bandit"
    assert r_bandit.status == "failed"
    assert r_bandit.findings == []
    assert "Unexpected scanner exception" in r_bandit.error

    # Secrets check
    assert r_secrets.scanner_name == "secrets"
    assert r_secrets.status == "success"
    assert len(r_secrets.findings) == 1

    # Dependency check
    assert r_dep.scanner_name == "dependency"
    assert r_dep.status == "skipped"

    # Aggregated findings
    all_findings = []
    for r in results:
        all_findings.extend(r.findings)

    assert len(all_findings) == 2  # 1 from Semgrep, 1 from Secrets

    # Aggregated status
    overall_status = aggregate_scanner_statuses(results)
    assert overall_status == "partial"
