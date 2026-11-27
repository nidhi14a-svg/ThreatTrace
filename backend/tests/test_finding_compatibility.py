"""Tests for Finding schema compatibility across all scanners and normalizer edge cases.

Verifies:
- Compliance with Dev B's canonical Finding schema (backend/app/schemas/finding.py)
- Manifest/file-level findings with line=None
- Nullable AI fields (explanation, recommendation)
- Unknown raw categories and fallback defaults
- Invalid or unknown severity/confidence values
- Evidence bounding to 1,000 characters
- Secret redaction before Finding instantiation
- Resilient normalization of malformed raw finding dictionaries
"""

import pytest
from app.scanners.normalizer import normalize_raw_finding
from app.schemas.finding import Finding


def test_canonical_finding_with_all_fields_populated():
    raw = {
        "id": "find_123456",
        "domain": "Web Application Security",
        "rule_id": "semgrep.python.fastapi.sqli",
        "title": "SQL Injection in User Route",
        "severity": "high",
        "file": "backend/app/api/routes/users.py",
        "line": 42,
        "evidence": "db.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        "confidence": "high",
        "explanation": "Untrusted user input concatenated directly into SQL statement.",
        "recommendation": "Use parameterized queries with prepared statements.",
        "tool": "semgrep",
        "raw_category": "security/injection",
    }
    finding = normalize_raw_finding(raw)

    assert isinstance(finding, Finding)
    assert finding.id == "find_123456"
    assert finding.domain == "Web Application Security"
    assert finding.rule_id == "semgrep.python.fastapi.sqli"
    assert finding.title == "SQL Injection in User Route"
    assert finding.severity == "high"
    assert finding.file == "backend/app/api/routes/users.py"
    assert finding.line == 42
    assert finding.evidence == "db.execute(f'SELECT * FROM users WHERE id = {user_id}')"
    assert finding.confidence == "high"
    assert finding.explanation == "Untrusted user input concatenated directly into SQL statement."
    assert finding.recommendation == "Use parameterized queries with prepared statements."
    assert finding.tool == "semgrep"
    assert finding.raw_category == "security/injection"


def test_finding_with_manifest_level_null_line_number():
    raw = {
        "rule_id": "osv.GHSA-1234",
        "title": "Vulnerable Dependency: cryptography",
        "severity": "critical",
        "file": "requirements.txt",
        "line": None,
        "evidence": "cryptography==2.8 is vulnerable to memory corruption",
        "tool": "osv-scanner",
    }
    finding = normalize_raw_finding(raw)

    assert isinstance(finding, Finding)
    assert finding.line is None
    assert finding.file == "requirements.txt"
    assert finding.severity == "critical"
    assert finding.tool == "osv-scanner"


def test_finding_with_string_digit_line_number_normalized_to_int():
    raw = {
        "rule_id": "bandit.B101",
        "file": "src/app.py",
        "line": "85",
        "tool": "bandit",
    }
    finding = normalize_raw_finding(raw)

    assert finding.line == 85
    assert isinstance(finding.line, int)


def test_finding_with_invalid_non_numeric_line_number_defaults_to_none():
    raw = {
        "rule_id": "custom.check",
        "file": "src/app.py",
        "line": "unknown_line",
        "tool": "custom-rules",
    }
    finding = normalize_raw_finding(raw)

    assert finding.line is None


def test_finding_nullable_ai_fields():
    raw = {
        "rule_id": "gitleaks.aws-key",
        "title": "Exposed AWS Key",
        "severity": "critical",
        "file": ".env",
        "line": 1,
        "evidence": "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
        "tool": "gitleaks",
    }
    finding = normalize_raw_finding(raw)

    assert finding.explanation is None
    assert finding.recommendation is None
    assert finding.raw_category is None


def test_finding_unknown_raw_category_preserved():
    raw = {
        "rule_id": "bandit.B608",
        "file": "src/db.py",
        "tool": "bandit",
        "raw_category": "CWE-89: SQL Injection",
    }
    finding = normalize_raw_finding(raw)

    assert finding.raw_category == "CWE-89: SQL Injection"


def test_finding_invalid_severity_falls_back_to_medium():
    raw = {
        "rule_id": "test.rule",
        "severity": "fatal_catastrophic",
        "file": "main.py",
        "tool": "custom",
    }
    finding = normalize_raw_finding(raw)

    assert finding.severity == "medium"


def test_finding_uppercase_severity_normalized():
    for upper_sev, expected in [
        ("CRITICAL", "critical"),
        ("HIGH", "high"),
        ("ERROR", "high"),
        ("WARNING", "medium"),
        ("MODERATE", "medium"),
        ("LOW", "low"),
        ("INFO", "low"),
    ]:
        raw = {"rule_id": "test", "severity": upper_sev, "file": "main.py"}
        finding = normalize_raw_finding(raw)
        assert finding.severity == expected


def test_finding_evidence_bounded_to_1000_chars():
    long_code = "A" * 2500
    raw = {
        "rule_id": "test.long_code",
        "file": "main.py",
        "evidence": long_code,
    }
    finding = normalize_raw_finding(raw)

    assert len(finding.evidence) == 1000
    assert finding.evidence.endswith("...")
    assert finding.evidence.startswith("A" * 997)


def test_finding_evidence_secret_redacted_before_finding_instantiation():
    raw_secret = "AWS_SECRET = 'AKIAIOSFODNN7EXAMPLE' and github='ghp_0123456789abcdefghijklmnopqrstuvwxyz'"
    raw = {
        "rule_id": "gitleaks.key",
        "file": "config.py",
        "evidence": raw_secret,
        "tool": "gitleaks",
    }
    finding = normalize_raw_finding(raw)

    assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence
    assert "ghp_0123456789abcdefghijklmnopqrstuvwxyz" not in finding.evidence
    assert "[REDACTED_AWS_KEY]" in finding.evidence or "[REDACTED" in finding.evidence


def test_finding_malformed_empty_raw_dict_produces_valid_finding():
    finding = normalize_raw_finding({}, default_tool="fallback_scanner")

    assert isinstance(finding, Finding)
    assert finding.id.startswith("find_")
    assert finding.domain == "General Security"
    assert finding.rule_id == "rule_unknown"
    assert finding.severity == "medium"
    assert finding.confidence == "medium"
    assert finding.file == "[UNKNOWN_FILE]"
    assert finding.line is None
    assert finding.evidence == ""
    assert finding.tool == "fallback_scanner"
