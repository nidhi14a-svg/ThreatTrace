import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult
from app.scanners.secrets_scanner import SecretsScanner


# ============================================================================
# Helpers & Sample Data
# ============================================================================


def create_mock_process(stdout_bytes: bytes, stderr_bytes: bytes, returncode: int = 0):
    """Create a mock asyncio subprocess."""
    process = MagicMock()
    process.returncode = returncode
    process.communicate = AsyncMock(return_value=(stdout_bytes, stderr_bytes))
    process.kill = MagicMock()
    process.wait = AsyncMock(return_value=returncode)
    return process


SAMPLE_GITLEAKS_JSON = [
    {
        "Description": "AWS Access Key ID",
        "StartLine": 14,
        "EndLine": 14,
        "StartColumn": 18,
        "EndColumn": 38,
        "Match": "AWS_ACCESS_KEY = \"AKIAIOSFODNN7EXAMPLE\"",
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "File": "backend/app/core/config.py",
        "SymlinkFile": "",
        "Commit": "",
        "Entropy": 3.73,
        "Author": "",
        "Email": "",
        "Date": "",
        "Message": "",
        "Tags": ["key", "AWS"],
        "RuleID": "aws-access-key-id",
        "Fingerprint": "backend/app/core/config.py:aws-access-key-id:14",
    },
    {
        "Description": "GitHub Personal Access Token",
        "StartLine": 52,
        "EndLine": 52,
        "StartColumn": 12,
        "EndColumn": 52,
        "Match": "GITHUB_TOKEN = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"",
        "Secret": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "File": "scripts/release.py",
        "Entropy": 4.12,
        "RuleID": "github-pat",
        "Fingerprint": "scripts/release.py:github-pat:52",
    },
]


# ============================================================================
# 1. BaseScanner Interface & Initialization
# ============================================================================


def test_secrets_scanner_satisfies_base_scanner_interface():
    """Verify SecretsScanner satisfies the BaseScanner abstract contract."""
    scanner = SecretsScanner()
    assert isinstance(scanner, BaseScanner)
    assert scanner.name == "secrets"
    assert scanner.scanner_name == "secrets"
    assert scanner.timeout_seconds == 60.0
    assert scanner.max_output_bytes == 10 * 1024 * 1024


# ============================================================================
# 2. Valid Findings Execution & In-Memory Redaction
# ============================================================================


@pytest.mark.anyio
async def test_valid_gitleaks_json_with_redaction(tmp_path: Path):
    """Verify parsing of valid Gitleaks JSON and mandatory in-memory credential redaction."""
    test_file = tmp_path / "config.py"
    test_file.write_text("dummy", encoding="utf-8")

    stdout_bytes = json.dumps(SAMPLE_GITLEAKS_JSON).encode("utf-8")
    # Gitleaks exits with 1 when leaks are found
    mock_proc = create_mock_process(stdout_bytes, b"", returncode=1)

    scanner = SecretsScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert isinstance(result, ScannerExecutionResult)
    assert result.status == "success"
    assert result.scanner_name == "secrets"
    assert len(result.findings) == 2
    assert result.error is None
    assert result.duration_seconds >= 0.0

    # Verify first finding (AWS Key) attributes and redaction
    f1 = result.findings[0]
    assert f1["scanner_name"] == "secrets"
    assert f1["rule_id"] == "gitleaks.aws-access-key-id"
    assert f1["title"] == "AWS Access Key ID"
    assert f1["severity"] == "CRITICAL"
    assert f1["raw_category"] == "secrets"
    assert f1["file"] == "backend/app/core/config.py"
    assert f1["line"] == 14
    assert f1["end_line"] == 14
    assert f1["col"] == 18
    assert f1["end_col"] == 38
    assert f1["entropy"] == 3.73

    # CRITICAL: Plaintext secret MUST NOT be in evidence
    assert "AKIAIOSFODNN7EXAMPLE" not in f1["evidence"]
    assert "[REDACTED]" in f1["evidence"] or "AKIA****************" in f1["evidence"]

    # Verify second finding (GitHub PAT) attributes and redaction
    f2 = result.findings[1]
    assert f2["rule_id"] == "gitleaks.github-pat"
    assert f2["severity"] == "HIGH"
    assert f2["file"] == "scripts/release.py"
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in f2["evidence"]


# ============================================================================
# 3. Clean Scan (Exit code 0, Zero Leaks)
# ============================================================================


@pytest.mark.anyio
async def test_empty_findings_clean_scan(tmp_path: Path):
    """Verify clean scan when Gitleaks detects zero secrets (exit code 0)."""
    test_file = tmp_path / "main.py"
    test_file.write_text("clean_code = True", encoding="utf-8")

    clean_output = json.dumps([]).encode("utf-8")
    mock_proc = create_mock_process(clean_output, b"", returncode=0)

    scanner = SecretsScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "success"
    assert result.findings == []
    assert result.error is None


# ============================================================================
# 4. Malformed JSON Handling
# ============================================================================


@pytest.mark.anyio
async def test_malformed_json_handling(tmp_path: Path):
    """Verify handling of invalid non-JSON output."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    malformed_output = b"Gitleaks Panic: could not parse directory tree"
    mock_proc = create_mock_process(malformed_output, b"stderr panic trace", returncode=2)

    scanner = SecretsScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert result.findings == []
    assert "Malformed Gitleaks JSON" in result.error
    assert "stderr panic trace" in result.error


@pytest.mark.anyio
async def test_malformed_json_invalid_primitive_root(tmp_path: Path):
    """Verify handling of JSON primitive root (e.g., a number or string)."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    primitive_json = b"12345"
    mock_proc = create_mock_process(primitive_json, b"", returncode=0)

    scanner = SecretsScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "expected JSON array or object" in result.error


# ============================================================================
# 5. Missing Gitleaks Executable
# ============================================================================


@pytest.mark.anyio
async def test_missing_gitleaks_executable_default(tmp_path: Path):
    """Verify default behavior when gitleaks binary is not on PATH (status='failed')."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    scanner = SecretsScanner(binary_path="nonexistent-gitleaks-binary")
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("not found")):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "Gitleaks executable not found" in result.error
    assert "nonexistent-gitleaks-binary" in result.error


@pytest.mark.anyio
async def test_missing_gitleaks_executable_skipped_policy(tmp_path: Path):
    """Verify behavior when configured to skip missing binary (status='skipped')."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    scanner = SecretsScanner(
        binary_path="nonexistent-gitleaks-binary",
        allow_skip_if_missing=True,
    )
    with patch("shutil.which", return_value=None):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "skipped"
    assert "executable not found" in result.error


# ============================================================================
# 6. Timeout Handling
# ============================================================================


@pytest.mark.anyio
async def test_gitleaks_execution_timeout(tmp_path: Path):
    """Verify timeout terminates subprocess and returns status='failed'."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    mock_proc = MagicMock()
    mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_proc.kill = MagicMock()
    mock_proc.wait = AsyncMock(return_value=-9)

    scanner = SecretsScanner(timeout_seconds=4.0)
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "timed out after 4.0 seconds" in result.error
    assert mock_proc.kill.called


# ============================================================================
# 7. Non-Zero Exit Code Handling & Partial Results
# ============================================================================


@pytest.mark.anyio
async def test_fatal_exit_code_without_findings(tmp_path: Path):
    """Verify fatal exit code >= 2 without findings returns status='failed'."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    mock_proc = create_mock_process(b"", b"Flag error: unknown flag --bad-flag", returncode=2)

    scanner = SecretsScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert result.findings == []
    assert "Flag error" in result.error


@pytest.mark.anyio
async def test_exit_code_ge_2_with_findings_returns_partial(tmp_path: Path):
    """Verify exit code >= 2 with parsed findings returns status='partial'."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    stdout_bytes = json.dumps(SAMPLE_GITLEAKS_JSON).encode("utf-8")
    mock_proc = create_mock_process(stdout_bytes, b"Unreadable directory warning", returncode=2)

    scanner = SecretsScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "partial"
    assert len(result.findings) == 2
    assert "Unreadable directory warning" in result.error


# ============================================================================
# 8. Missing Optional Finding Fields Handling
# ============================================================================


@pytest.mark.anyio
async def test_findings_with_missing_optional_fields(tmp_path: Path):
    """Verify minimal finding item missing line numbers, entropy, match parses gracefully."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    minimal_output = [
        {
            "RuleID": "generic-secret",
            "File": "token.txt",
        }
    ]
    mock_proc = create_mock_process(json.dumps(minimal_output).encode("utf-8"), b"", returncode=1)

    scanner = SecretsScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "success"
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["rule_id"] == "gitleaks.generic-secret"
    assert f["file"] == "token.txt"
    assert f["line"] is None
    assert f["end_line"] is None
    assert f["col"] is None
    assert f["end_col"] is None
    assert f["severity"] == "MEDIUM"
    assert f["evidence"] == "[REDACTED]"
    assert f["entropy"] is None


# ============================================================================
# 9. Path Security & Traversal Prevention
# ============================================================================


@pytest.mark.anyio
async def test_correct_relative_path_handling(tmp_path: Path):
    """Verify paths inside workspace are properly normalized to POSIX relative paths."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    abs_inside = str(tmp_path / "config" / "credentials.json")

    path_test_output = [
        {"RuleID": "r1", "File": "api/keys.py"},
        {"RuleID": "r2", "File": abs_inside},
        {"RuleID": "r3", "File": "./secrets.env"},
    ]
    mock_proc = create_mock_process(json.dumps(path_test_output).encode("utf-8"), b"", returncode=1)

    scanner = SecretsScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "success"
    assert len(result.findings) == 3
    assert result.findings[0]["file"] == "api/keys.py"
    assert result.findings[1]["file"] == "config/credentials.json"
    assert result.findings[2]["file"] == "secrets.env"


@pytest.mark.anyio
async def test_rejection_of_paths_outside_workspace(tmp_path: Path):
    """Verify directory traversal outside workspace is safely rejected."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    traversal_output = [
        {"RuleID": "r1", "File": "../../etc/shadow"},
        {"RuleID": "r2", "File": "/etc/passwd"},
    ]
    mock_proc = create_mock_process(json.dumps(traversal_output).encode("utf-8"), b"", returncode=1)

    scanner = SecretsScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "success"
    assert len(result.findings) == 2
    assert result.findings[0]["file"] == "[REJECTED_OUTSIDE_WORKSPACE]"
    assert result.findings[1]["file"] == "[REJECTED_OUTSIDE_WORKSPACE]"


# ============================================================================
# 10. Output Limits & Safe Error Messages
# ============================================================================


@pytest.mark.anyio
async def test_safe_and_bounded_error_messages(tmp_path: Path):
    """Verify ANSI escape codes are stripped and error length is capped."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    noisy_stderr = b"\x1b[31mError:\x1b[0m Gitleaks error.\n" + (b"stack trace\n" * 100)
    mock_proc = create_mock_process(b"", noisy_stderr, returncode=2)

    scanner = SecretsScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "\x1b[" not in result.error
    assert len(result.error) <= 550


@pytest.mark.anyio
async def test_bounded_stdout_output_handling(tmp_path: Path):
    """Verify execution fails safely when stdout exceeds memory ceiling."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    huge_stdout = b"C" * 2000
    mock_proc = create_mock_process(huge_stdout, b"", returncode=0)

    scanner = SecretsScanner(max_output_bytes=1000)
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "exceeded maximum limit" in result.error


# ============================================================================
# 11. Workspace Validation & Empty Handling
# ============================================================================


@pytest.mark.anyio
async def test_workspace_validation_non_existent():
    """Verify non-existent workspace returns status='skipped' with error=None."""
    scanner = SecretsScanner()
    result = await scanner.scan("/nonexistent/directory/xyz123")
    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None


@pytest.mark.anyio
async def test_workspace_validation_file_not_dir(tmp_path: Path):
    """Verify workspace pointing to a file returns status='failed'."""
    file_path = tmp_path / "file.txt"
    file_path.write_text("content", encoding="utf-8")

    scanner = SecretsScanner()
    result = await scanner.scan(str(file_path))
    assert result.status == "failed"
    assert "is not a directory" in result.error


@pytest.mark.anyio
async def test_workspace_validation_empty_string():
    """Verify empty string workspace returns status='failed'."""
    scanner = SecretsScanner()
    result = await scanner.scan("")
    assert result.status == "failed"
    assert "cannot be empty" in result.error


@pytest.mark.anyio
async def test_empty_workspace_returns_skipped(tmp_path: Path):
    """Verify empty directory with zero files returns status='skipped'."""
    scanner = SecretsScanner()
    result = await scanner.scan(str(tmp_path))
    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None


# ============================================================================
# 12. Safe Subprocess Arguments (No shell=True, --no-git, --redact)
# ============================================================================


@pytest.mark.anyio
async def test_safe_subprocess_arguments_invoked(tmp_path: Path):
    """Verify command is passed as an argument list and shell=True is not used."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    clean_bytes = json.dumps([]).encode("utf-8")
    mock_proc = create_mock_process(clean_bytes, b"", returncode=0)

    scanner = SecretsScanner(config_path="/etc/gitleaks.toml")
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        await scanner.scan(str(tmp_path))

        assert mock_exec.called
        args, kwargs = mock_exec.call_args
        assert args[0] == "gitleaks"
        assert args[1] == "dir"
        assert "--no-git" not in args
        assert "--report-format" in args
        assert "json" in args
        assert "--redact" in args
        assert "--config" in args
        assert "/etc/gitleaks.toml" in args
        assert kwargs.get("shell") is not True
        assert kwargs.get("cwd") == str(tmp_path.resolve())
