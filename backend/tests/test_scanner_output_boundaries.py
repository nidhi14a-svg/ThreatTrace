import json
from pathlib import Path

import pytest

from app.scanners.bandit_scanner import BanditScanner
from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult
from app.scanners.dependency_scanner import DependencyScanner
from app.scanners.secrets_scanner import SecretsScanner
from app.scanners.semgrep_scanner import SemgrepScanner


# ============================================================================
# 1. Path Sanitization & Traversal Rejection Boundaries
# ============================================================================


def test_sanitize_path_relative_and_posix_normalization(tmp_path: Path):
    """Verify relative paths are normalized with forward slashes."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    assert BaseScanner.sanitize_path("app/main.py", workspace) == "app/main.py"
    assert BaseScanner.sanitize_path("nested/deep/file.ts", workspace) == "nested/deep/file.ts"
    assert BaseScanner.sanitize_path("requirements.txt", workspace) == "requirements.txt"


def test_sanitize_path_absolute_path_inside_workspace(tmp_path: Path):
    """Verify absolute paths within the workspace resolve to relative POSIX paths."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    inside_file = workspace / "backend" / "app" / "config.py"

    assert BaseScanner.sanitize_path(str(inside_file), workspace) == "backend/app/config.py"


def test_sanitize_path_rejects_parent_directory_traversal(tmp_path: Path):
    """Verify paths attempting to escape workspace are rejected."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Relative directory traversal
    assert BaseScanner.sanitize_path("../../etc/passwd", workspace) == "[REJECTED_OUTSIDE_WORKSPACE]"
    assert BaseScanner.sanitize_path("../outside.py", workspace) == "[REJECTED_OUTSIDE_WORKSPACE]"

    # Absolute path outside workspace
    outside = tmp_path / "other_folder" / "secret.env"
    assert BaseScanner.sanitize_path(str(outside), workspace) == "[REJECTED_OUTSIDE_WORKSPACE]"


def test_sanitize_path_handles_empty_or_invalid_inputs(tmp_path: Path):
    """Verify empty or invalid paths return safe sentinel values."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    assert BaseScanner.sanitize_path("", workspace) == "[UNKNOWN_PATH]"
    assert BaseScanner.sanitize_path(None, workspace) == "[UNKNOWN_PATH]"


# ============================================================================
# 2. Evidence Bounding Boundaries
# ============================================================================


def test_bound_evidence_leaves_short_evidence_intact():
    """Verify evidence within limits is not modified."""
    evidence = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
    assert BaseScanner.bound_evidence(evidence) == evidence


def test_bound_evidence_truncates_long_evidence_to_1000_chars():
    """Verify evidence exceeding 1,000 characters is safely truncated."""
    long_evidence = "A" * 2500
    bounded = BaseScanner.bound_evidence(long_evidence, max_chars=1000)

    assert len(bounded) == 1000
    assert bounded.endswith("...")
    assert bounded.startswith("AAA")


def test_bound_evidence_handles_empty_string():
    """Verify empty or null evidence produces safe empty string."""
    assert BaseScanner.bound_evidence("") == ""
    assert BaseScanner.bound_evidence(None) == ""


# ============================================================================
# 3. In-Memory Credential Redaction Boundaries
# ============================================================================


def test_redact_evidence_masks_aws_keys():
    """Verify AWS access key IDs are masked in evidence snippets."""
    snippet = "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
    redacted = BaseScanner.redact_evidence(snippet)

    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "AKIA****************" in redacted


def test_redact_evidence_masks_github_pats():
    """Verify GitHub personal access tokens are masked in evidence snippets."""
    snippet = "token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'"
    redacted = BaseScanner.redact_evidence(snippet)

    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in redacted
    assert "[REDACTED_GITHUB_TOKEN]" in redacted


def test_redact_evidence_masks_private_keys():
    """Verify full private key blocks are replaced in evidence snippets."""
    key_block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1234567890abcdefghijklmnopqrstuvwxyz\n"
        "-----END RSA PRIVATE KEY-----"
    )
    snippet = f"key_data = '''{key_block}'''"
    redacted = BaseScanner.redact_evidence(snippet)

    assert "MIIEowIBAAKCAQEA0Y1234567890" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted


def test_redact_evidence_masks_slack_webhooks():
    """Verify Slack webhook URLs are sanitized."""
    snippet = "webhook = 'https://hooks.slack.com/services/T000/B000/XXXXX'"
    redacted = BaseScanner.redact_evidence(snippet)

    assert "T000/B000/XXXXX" not in redacted
    assert "https://hooks.slack.com/services/[REDACTED]" in redacted


def test_redact_evidence_masks_bearer_tokens():
    """Verify Authorization Bearer tokens are sanitized."""
    snippet = "headers = {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID'} "
    redacted = BaseScanner.redact_evidence(snippet)

    assert "eyJhbGciOiJIUzI1NiIsInR5cCI" not in redacted
    assert "Bearer [REDACTED_BEARER_TOKEN]" in redacted


def test_redact_evidence_leaves_clean_code_intact():
    """Verify standard benign code is not corrupted by the redaction filter."""
    clean_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    assert BaseScanner.redact_evidence(clean_code) == clean_code


# ============================================================================
# 4. Safe Error Bounding Boundaries
# ============================================================================


def test_bound_error_trims_and_bounds_long_messages():
    """Verify error messages exceeding limits are truncated to prevent secret dumps."""
    huge_error = "Traceback (most recent call last):\n" + ("  File 'test.py', line 1\n" * 200)
    bounded = BaseScanner.bound_error(huge_error, max_chars=1000)

    assert len(bounded) == 1000
    assert bounded.endswith("...")


def test_bound_error_returns_none_for_empty_strings():
    """Verify empty or whitespace error strings return None."""
    assert BaseScanner.bound_error(None) is None
    assert BaseScanner.bound_error("") is None
    assert BaseScanner.bound_error("   ") is None


# ============================================================================
# 5. Safe JSON Payload Extraction Boundaries
# ============================================================================


def test_parse_json_safely_extracts_clean_json_object():
    """Verify standard JSON object is parsed directly."""
    raw = '{"status": "ok", "count": 42}'
    data = BaseScanner.parse_json_safely(raw)
    assert data == {"status": "ok", "count": 42}


def test_parse_json_safely_extracts_clean_json_array():
    """Verify standard JSON array is parsed directly."""
    raw = '[{"id": 1}, {"id": 2}]'
    data = BaseScanner.parse_json_safely(raw)
    assert len(data) == 2
    assert data[0]["id"] == 1


def test_parse_json_safely_handles_cli_preamble_and_banner_text():
    """Verify JSON embedded within informational CLI banner text is extracted."""
    raw_with_banner = (
        "Semgrep 1.50.0 - analyzing code...\n"
        "Loading rules from p/default...\n"
        '{"results": [{"check_id": "test.rule"}], "errors": []}\n'
        "Done in 0.45s."
    )
    data = BaseScanner.parse_json_safely(raw_with_banner)
    assert isinstance(data, dict)
    assert "results" in data
    assert data["results"][0]["check_id"] == "test.rule"


def test_parse_json_safely_returns_none_for_invalid_json():
    """Verify malformed JSON returns None instead of raising unhandled exceptions."""
    assert BaseScanner.parse_json_safely("Fatal error: cannot open database") is None
    assert BaseScanner.parse_json_safely("{invalid json without quotes}") is None
    assert BaseScanner.parse_json_safely("") is None
    assert BaseScanner.parse_json_safely(None) is None


# ============================================================================
# 6. Cross-Scanner Output Schema Invariant Verification
# ============================================================================


def test_all_scanner_classes_define_required_identity_and_methods():
    """Verify all four implemented scanners provide consistent identity and interface."""
    scanners = [
        SemgrepScanner(),
        BanditScanner(),
        SecretsScanner(),
        DependencyScanner(),
    ]

    expected_names = {"semgrep", "bandit", "secrets", "dependency"}
    actual_names = {s.name for s in scanners}
    assert actual_names == expected_names

    for s in scanners:
        assert isinstance(s, BaseScanner)
        assert s.scanner_name == s.name
        assert hasattr(s, "create_result")
        assert hasattr(s, "sanitize_path")
        assert hasattr(s, "bound_evidence")
        assert hasattr(s, "redact_evidence")
