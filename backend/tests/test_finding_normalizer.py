import pytest

from app.scanners.base_scanner import ScannerExecutionResult
from app.scanners.normalizer import normalize_raw_finding, normalize_scanner_result
from app.schemas.finding import Finding


def test_normalize_semgrep_raw_finding():
    """Verify normalization of Semgrep raw finding dictionary."""
    raw_semgrep = {
        "rule_id": "semgrep.sql-injection",
        "title": "SQL Injection in User Search",
        "severity": "ERROR",
        "file": "backend\\app\\routes\\search.py",
        "line": 42,
        "evidence": "query = f'SELECT * FROM users WHERE email = {email}'",
        "confidence": "HIGH",
        "raw_category": "security/injection",
    }

    finding = normalize_raw_finding(raw_semgrep, default_tool="semgrep")

    assert isinstance(finding, Finding)
    assert finding.tool == "semgrep"
    assert finding.rule_id == "semgrep.sql-injection"
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert finding.file == "backend/app/routes/search.py"
    assert finding.line == 42
    assert finding.raw_category == "security/injection"
    assert finding.explanation is None
    assert finding.recommendation is None


def test_normalize_bandit_raw_finding():
    """Verify normalization of Bandit raw finding dictionary."""
    raw_bandit = {
        "test_id": "B608",
        "issue_text": "Possible SQL injection vector through string formatting",
        "issue_severity": "HIGH",
        "filename": "app/services/client.py",
        "line_number": 28,
        "code": "cursor.execute(sql % val)",
        "issue_confidence": "HIGH",
        "test_name": "hardcoded_sql_expressions",
        "scanner_name": "bandit",
    }

    finding = normalize_raw_finding(raw_bandit)

    assert finding.tool == "bandit"
    assert finding.rule_id == "B608"
    assert finding.severity == "high"
    assert finding.line == 28
    assert finding.raw_category == "hardcoded_sql_expressions"


def test_normalize_gitleaks_raw_finding_with_redaction():
    """Verify Gitleaks raw finding redacts credentials and normalizes path."""
    raw_gitleaks = {
        "rule_id": "gitleaks.aws-access-key-id",
        "title": "AWS Access Key ID",
        "severity": "critical",
        "file": "config.py",
        "line": 14,
        "evidence": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
        "confidence": "high",
        "tool": "gitleaks",
        "raw_category": "aws-access-key-id",
    }

    finding = normalize_raw_finding(raw_gitleaks)

    assert finding.tool == "gitleaks"
    assert finding.severity == "critical"
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence
    assert "AKIA****************" in finding.evidence


def test_normalize_osv_scanner_finding_with_null_line():
    """Verify OSV-Scanner dependency finding handles line=None gracefully."""
    raw_osv = {
        "rule_id": "GHSA-g3rq-g295-4838",
        "title": "Jinja2 vulnerable to ReDoS",
        "severity": "high",
        "file": "requirements.txt",
        "line": None,
        "evidence": "Dependency 'jinja2' version '2.11.2' matches advisory GHSA-g3rq-g295-4838",
        "confidence": "medium",
        "tool": "osv-scanner",
        "raw_category": "dependency_vulnerability",
    }

    finding = normalize_raw_finding(raw_osv)

    assert finding.tool == "osv-scanner"
    assert finding.line is None
    assert finding.raw_category == "dependency_vulnerability"


def test_normalize_scanner_result_helper():
    """Verify normalize_scanner_result converts all findings in a result."""
    result = ScannerExecutionResult(
        scanner_name="custom-rules",
        status="success",
        findings=[
            {
                "rule_id": "custom.web.sql-injection-fstring",
                "title": "SQL Injection",
                "severity": "high",
                "file": "main.py",
                "line": 10,
                "evidence": "query = f'SELECT {x}'",
                "confidence": "high",
            },
            {
                "rule_id": "custom.secrets.hardcoded-password",
                "title": "Password",
                "severity": "high",
                "file": "auth.py",
                "line": 5,
                "evidence": "password = 'secret'",
                "confidence": "medium",
            },
        ],
        duration_seconds=0.2,
    )

    findings = normalize_scanner_result(result)
    assert len(findings) == 2
    assert all(isinstance(f, Finding) for f in findings)
    assert findings[0].tool == "custom-rules"
    assert findings[1].tool == "custom-rules"
