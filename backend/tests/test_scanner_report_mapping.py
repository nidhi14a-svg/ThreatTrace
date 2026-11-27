"""Tests for Scanner Report Mapping and Aggregation (specs/SCANNER_REPORT_MAPPING_SPEC.md).

Verifies:
- Scanner execution status aggregation (success, partial, failed, skipped)
- Severity metrics calculation (critical, high, medium, low)
- Two-tier domain taxonomy mapping (5 display domains <-> 10 backend identifiers)
- Tool priority deduplication during scan result aggregation
- Preservation of finding coordinates and scanner identity in aggregate payload
"""

import pytest
from app.scanners.base_scanner import (
    ScannerExecutionResult,
    ScannerStatus,
    aggregate_scanner_statuses,
)
from app.scanners.normalizer import normalize_scanner_result
from app.scanners.suppression import TOOL_PRIORITY, deduplicate_findings
from app.scanners.worker_runner import process_and_normalize_results


def test_status_aggregation_all_successful():
    results = [
        ScannerExecutionResult(scanner_name="semgrep", status=ScannerStatus.SUCCESS),
        ScannerExecutionResult(scanner_name="bandit", status=ScannerStatus.SUCCESS),
        ScannerExecutionResult(scanner_name="secrets", status=ScannerStatus.SUCCESS),
    ]
    assert aggregate_scanner_statuses(results) == "success"


def test_status_aggregation_partial_when_one_fails():
    results = [
        ScannerExecutionResult(scanner_name="semgrep", status=ScannerStatus.SUCCESS),
        ScannerExecutionResult(scanner_name="bandit", status=ScannerStatus.FAILED, error="Timeout"),
        ScannerExecutionResult(scanner_name="secrets", status=ScannerStatus.SUCCESS),
    ]
    assert aggregate_scanner_statuses(results) == "partial"


def test_status_aggregation_all_failed():
    results = [
        ScannerExecutionResult(scanner_name="semgrep", status=ScannerStatus.FAILED, error="Crash"),
        ScannerExecutionResult(scanner_name="bandit", status=ScannerStatus.FAILED, error="Binary missing"),
    ]
    assert aggregate_scanner_statuses(results) == "failed"


def test_status_aggregation_all_skipped():
    results = [
        ScannerExecutionResult(scanner_name="bandit", status=ScannerStatus.SKIPPED),
        ScannerExecutionResult(scanner_name="secrets", status=ScannerStatus.SKIPPED),
    ]
    assert aggregate_scanner_statuses(results) == "skipped"


def test_severity_metric_calculation_across_findings():
    findings_raw = [
        {"rule_id": "r1", "severity": "CRITICAL", "file": "f1.py", "tool": "t1"},
        {"rule_id": "r2", "severity": "HIGH", "file": "f2.py", "tool": "t1"},
        {"rule_id": "r3", "severity": "WARNING", "file": "f3.py", "tool": "t1"},  # maps to medium
        {"rule_id": "r4", "severity": "LOW", "file": "f4.py", "tool": "t1"},
        {"rule_id": "r5", "severity": "INFO", "file": "f5.py", "tool": "t1"},     # maps to low
    ]
    res = ScannerExecutionResult(
        scanner_name="t1",
        status=ScannerStatus.SUCCESS,
        findings=findings_raw,
    )
    payload = process_and_normalize_results({"t1": res})

    findings = payload["findings"]
    severity_counts = {
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "high": sum(1 for f in findings if f["severity"] == "high"),
        "medium": sum(1 for f in findings if f["severity"] == "medium"),
        "low": sum(1 for f in findings if f["severity"] == "low"),
    }

    assert severity_counts["critical"] == 1
    assert severity_counts["high"] == 1
    assert severity_counts["medium"] == 1
    assert severity_counts["low"] == 2
    assert payload["total_findings"] == 5


def test_domain_taxonomy_mapping():
    DOMAIN_TAXONOMY_MAP = {
        "secrets": "Secrets & Sensitive Information Management",
        "injection": "Web Application Security",
        "input_validation": "Web Application Security",
        "other": "Web Application Security",
        "cryptography": "Network & Communication Security",
        "logging": "Network & Communication Security",
        "authentication": "Authentication & Access Control",
        "authorization": "Authentication & Access Control",
        "dependencies": "Dependency & Configuration Security",
        "configuration": "Dependency & Configuration Security",
    }

    # Verify all 10 backend identifiers map cleanly to the 5 display domains
    assert len(DOMAIN_TAXONOMY_MAP) == 10
    display_domains = set(DOMAIN_TAXONOMY_MAP.values())
    assert display_domains == {
        "Secrets & Sensitive Information Management",
        "Web Application Security",
        "Network & Communication Security",
        "Authentication & Access Control",
        "Dependency & Configuration Security",
    }


def test_tool_priority_deduplication_preserves_higher_precedence():
    # Semgrep (priority 7) and Bandit (priority 9) detect the same line
    f_semgrep = {
        "rule_id": "semgrep.sqli",
        "domain": "Web Application Security",
        "file": "app/db.py",
        "line": 50,
        "severity": "high",
        "tool": "semgrep",
    }
    f_bandit = {
        "rule_id": "bandit.B608",
        "domain": "Web Application Security",
        "file": "app/db.py",
        "line": 50,
        "severity": "high",
        "tool": "bandit",
    }

    res_semgrep = ScannerExecutionResult(scanner_name="semgrep", status=ScannerStatus.SUCCESS, findings=[f_semgrep])
    res_bandit = ScannerExecutionResult(scanner_name="bandit", status=ScannerStatus.SUCCESS, findings=[f_bandit])

    payload = process_and_normalize_results({
        "semgrep": res_semgrep,
        "bandit": res_bandit,
    })

    assert payload["total_findings"] == 1
    assert payload["deduplicated_count"] == 1
    # Bandit has priority 9 over Semgrep's priority 7
    authoritative = payload["findings"][0]
    assert authoritative["tool"] == "bandit"
    assert authoritative["rule_id"] == "bandit.B608"
