import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanners.bandit_scanner import BanditScanner
from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult


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


SAMPLE_BANDIT_JSON = {
    "results": [
        {
            "code": "28 response = requests.get(api_url, verify=False)\n",
            "filename": "app/services/client.py",
            "issue_confidence": "HIGH",
            "issue_cwe": {
                "id": 295,
                "link": "https://cwe.mitre.org/data/definitions/295.html",
            },
            "issue_severity": "HIGH",
            "issue_text": "Requests call with verify=False disabling SSL certificate checks.",
            "line_number": 28,
            "line_range": [28],
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b501_request_with_no_cert_validation.html",
            "test_id": "B501",
            "test_name": "request_with_no_cert_validation",
        },
        {
            "code": "104 hash = hashlib.md5(password.encode()).hexdigest()\n",
            "filename": "app/auth/hash.py",
            "issue_confidence": "HIGH",
            "issue_cwe": {
                "id": 327,
                "link": "https://cwe.mitre.org/data/definitions/327.html",
            },
            "issue_severity": "MEDIUM",
            "issue_text": "Use of weak MD5 hash function.",
            "line_number": 104,
            "line_range": [104],
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b303_md5.html",
            "test_id": "B303",
            "test_name": "md5",
        },
    ],
    "errors": [],
    "metrics": {},
}


# ============================================================================
# 1. BaseScanner Interface & Initialization
# ============================================================================


def test_bandit_scanner_satisfies_base_scanner_interface():
    """Verify BanditScanner satisfies the BaseScanner abstract contract."""
    scanner = BanditScanner()
    assert isinstance(scanner, BaseScanner)
    assert scanner.name == "bandit"
    assert scanner.scanner_name == "bandit"
    assert scanner.timeout_seconds == 60.0
    assert scanner.max_output_bytes == 10 * 1024 * 1024
    assert ".venv" in scanner.excluded_paths


# ============================================================================
# 2. Valid Findings Execution (Exit code 0 and Exit code 1)
# ============================================================================


@pytest.mark.anyio
async def test_valid_bandit_json_with_multiple_findings(tmp_path: Path):
    """Verify parsing of valid Bandit JSON containing multiple findings."""
    py_file = tmp_path / "app.py"
    py_file.write_text("import requests\n", encoding="utf-8")

    stdout_bytes = json.dumps(SAMPLE_BANDIT_JSON).encode("utf-8")
    # Bandit exits with 1 when issues are found
    mock_proc = create_mock_process(stdout_bytes, b"", returncode=1)

    scanner = BanditScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert isinstance(result, ScannerExecutionResult)
    assert result.status == "success"
    assert result.scanner_name == "bandit"
    assert len(result.findings) == 2
    assert result.error is None
    assert result.duration_seconds >= 0.0

    # Verify first finding attributes
    f1 = result.findings[0]
    assert f1["scanner_name"] == "bandit"
    assert f1["rule_id"] == "bandit.B501"
    assert f1["severity"] == "HIGH"
    assert f1["confidence"] == "HIGH"
    assert f1["raw_category"] == "request_with_no_cert_validation"
    assert f1["file"] == "app/services/client.py"
    assert f1["line"] == 28
    assert f1["line_range"] == [28]
    assert "verify=False" in f1["evidence"]
    assert "Requests call" in f1["message"]
    assert f1["metadata"]["test_id"] == "B501"

    # Verify second finding attributes
    f2 = result.findings[1]
    assert f2["rule_id"] == "bandit.B303"
    assert f2["severity"] == "MEDIUM"
    assert f2["confidence"] == "HIGH"
    assert f2["raw_category"] == "md5"
    assert f2["line"] == 104


# ============================================================================
# 3. Clean Scan (Exit code 0, Empty Findings)
# ============================================================================


@pytest.mark.anyio
async def test_empty_findings_clean_scan(tmp_path: Path):
    """Verify clean scan when Bandit detects zero issues (exit code 0)."""
    py_file = tmp_path / "main.py"
    py_file.write_text("print('clean code')", encoding="utf-8")

    clean_output = json.dumps({"results": [], "errors": [], "metrics": {}}).encode("utf-8")
    mock_proc = create_mock_process(clean_output, b"", returncode=0)

    scanner = BanditScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "success"
    assert result.findings == []
    assert result.error is None


# ============================================================================
# 4. Malformed JSON & Non-Dict Output Handling
# ============================================================================


@pytest.mark.anyio
async def test_malformed_json_handling(tmp_path: Path):
    """Verify handling of invalid non-JSON output."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    malformed_output = b"Bandit Fatal Error: AST syntax parser broken"
    mock_proc = create_mock_process(malformed_output, b"stderr diagnostic", returncode=2)

    scanner = BanditScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert result.findings == []
    assert "Malformed Bandit JSON" in result.error
    assert "stderr diagnostic" in result.error


@pytest.mark.anyio
async def test_malformed_json_non_dict_root(tmp_path: Path):
    """Verify handling of JSON array root instead of object."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    non_dict_json = json.dumps(["error1", "error2"]).encode("utf-8")
    mock_proc = create_mock_process(non_dict_json, b"", returncode=0)

    scanner = BanditScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "expected root JSON object" in result.error


# ============================================================================
# 5. Missing Bandit Executable
# ============================================================================


@pytest.mark.anyio
async def test_missing_bandit_executable_default(tmp_path: Path):
    """Verify default behavior when bandit binary is not on PATH (status='failed')."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    scanner = BanditScanner(binary_path="nonexistent-bandit-binary")
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("not found")):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "Bandit executable not found" in result.error
    assert "nonexistent-bandit-binary" in result.error


@pytest.mark.anyio
async def test_missing_bandit_executable_skipped_policy(tmp_path: Path):
    """Verify behavior when configured to skip missing binary (status='skipped')."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    scanner = BanditScanner(
        binary_path="nonexistent-bandit-binary",
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
async def test_bandit_execution_timeout(tmp_path: Path):
    """Verify timeout terminates subprocess and returns status='failed'."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    mock_proc = MagicMock()
    mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_proc.kill = MagicMock()
    mock_proc.wait = AsyncMock(return_value=-9)

    scanner = BanditScanner(timeout_seconds=3.0)
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "timed out after 3.0 seconds" in result.error
    assert mock_proc.kill.called


# ============================================================================
# 7. Non-Zero Exit Code Handling & Partial Results
# ============================================================================


@pytest.mark.anyio
async def test_non_zero_exit_without_findings(tmp_path: Path):
    """Verify fatal exit code >= 2 without findings returns status='failed'."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    mock_proc = create_mock_process(b"", b"Usage error: unknown option", returncode=2)

    scanner = BanditScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert result.findings == []
    assert "Usage error" in result.error


@pytest.mark.anyio
async def test_exit_code_ge_2_with_findings_returns_partial(tmp_path: Path):
    """Verify exit code >= 2 with parsed findings returns status='partial'."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    stdout_bytes = json.dumps(SAMPLE_BANDIT_JSON).encode("utf-8")
    mock_proc = create_mock_process(stdout_bytes, b"Partial runtime warning", returncode=2)

    scanner = BanditScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "partial"
    assert len(result.findings) == 2
    assert "Partial runtime warning" in result.error


@pytest.mark.anyio
async def test_bandit_errors_in_json_returns_partial(tmp_path: Path):
    """Verify syntax errors in Bandit JSON return status='partial'."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    output_with_errors = {
        "results": [SAMPLE_BANDIT_JSON["results"][0]],
        "errors": [{"filename": "legacy.py", "reason": "invalid syntax"}],
        "metrics": {},
    }
    mock_proc = create_mock_process(json.dumps(output_with_errors).encode("utf-8"), b"", returncode=1)

    scanner = BanditScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "partial"
    assert len(result.findings) == 1
    assert "syntax/parse warnings on 1 file(s)" in result.error


# ============================================================================
# 8. Missing Optional Finding Fields Handling
# ============================================================================


@pytest.mark.anyio
async def test_findings_with_missing_optional_fields(tmp_path: Path):
    """Verify minimal finding item missing line_number, cwe, code parses gracefully."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    minimal_output = {
        "results": [
            {
                "test_id": "B101",
                "filename": "asserts.py",
                "issue_text": "Use of assert detected",
            }
        ],
        "errors": [],
    }
    mock_proc = create_mock_process(json.dumps(minimal_output).encode("utf-8"), b"", returncode=0)

    scanner = BanditScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "success"
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["rule_id"] == "bandit.B101"
    assert f["file"] == "asserts.py"
    assert f["line"] is None
    assert f["line_range"] == []
    assert f["severity"] == "MEDIUM"
    assert f["confidence"] == "MEDIUM"
    assert f["raw_category"] is None
    assert f["evidence"] == ""
    assert f["metadata"]["test_id"] == "B101"


# ============================================================================
# 9. Path Security & Traversal Prevention
# ============================================================================


@pytest.mark.anyio
async def test_correct_relative_path_handling(tmp_path: Path):
    """Verify paths inside workspace are properly normalized to POSIX relative paths."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    abs_inside = str(tmp_path / "app" / "models.py")

    path_test_output = {
        "results": [
            {"test_id": "B101", "filename": "core/security.py"},
            {"test_id": "B102", "filename": abs_inside},
            {"test_id": "B103", "filename": "./utils/helper.py"},
        ],
        "errors": [],
    }
    mock_proc = create_mock_process(json.dumps(path_test_output).encode("utf-8"), b"", returncode=0)

    scanner = BanditScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "success"
    assert len(result.findings) == 3
    assert result.findings[0]["file"] == "core/security.py"
    assert result.findings[1]["file"] == "app/models.py"
    assert result.findings[2]["file"] == "utils/helper.py"


@pytest.mark.anyio
async def test_rejection_of_paths_outside_workspace(tmp_path: Path):
    """Verify directory traversal outside workspace is safely rejected."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    traversal_output = {
        "results": [
            {"test_id": "B101", "filename": "../../etc/shadow"},
            {"test_id": "B102", "filename": "/etc/passwd"},
        ],
        "errors": [],
    }
    mock_proc = create_mock_process(json.dumps(traversal_output).encode("utf-8"), b"", returncode=0)

    scanner = BanditScanner()
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
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    noisy_stderr = b"\x1b[31mError:\x1b[0m Fatal crash.\n" + (b"long traceback\n" * 100)
    mock_proc = create_mock_process(b"", noisy_stderr, returncode=2)

    scanner = BanditScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "\x1b[" not in result.error
    assert len(result.error) <= 550


@pytest.mark.anyio
async def test_bounded_stdout_output_handling(tmp_path: Path):
    """Verify execution fails safely when stdout exceeds memory ceiling."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    huge_stdout = b"B" * 2000
    mock_proc = create_mock_process(huge_stdout, b"", returncode=0)

    scanner = BanditScanner(max_output_bytes=1000)
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "exceeded maximum output limit" in result.error


# ============================================================================
# 11. Workspace Validation & Python Source Detection
# ============================================================================


@pytest.mark.anyio
async def test_workspace_validation_non_existent():
    """Verify non-existent workspace returns status='skipped' with error=None."""
    scanner = BanditScanner()
    result = await scanner.scan("/nonexistent/directory/xyz123")
    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None


@pytest.mark.anyio
async def test_workspace_validation_file_not_dir(tmp_path: Path):
    """Verify workspace pointing to a file returns status='failed'."""
    file_path = tmp_path / "file.txt"
    file_path.write_text("content", encoding="utf-8")

    scanner = BanditScanner()
    result = await scanner.scan(str(file_path))
    assert result.status == "failed"
    assert "is not a directory" in result.error


@pytest.mark.anyio
async def test_workspace_validation_empty_string():
    """Verify empty string workspace returns status='failed'."""
    scanner = BanditScanner()
    result = await scanner.scan("")
    assert result.status == "failed"
    assert "cannot be empty" in result.error


@pytest.mark.anyio
async def test_workspace_without_python_files_returns_skipped(tmp_path: Path):
    """Verify workspace containing no Python files (.py) is skipped without running Bandit."""
    # Only JS and JSON files
    (tmp_path / "index.js").write_text("console.log('hi')", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")

    scanner = BanditScanner()
    # No subprocess call should be made
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        result = await scanner.scan(str(tmp_path))
        assert not mock_exec.called

    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None


# ============================================================================
# 12. Safe Subprocess Arguments (No shell=True)
# ============================================================================


@pytest.mark.anyio
async def test_safe_subprocess_arguments_invoked(tmp_path: Path):
    """Verify command is passed as an argument list and shell=True is not used."""
    py_file = tmp_path / "main.py"
    py_file.write_text("code", encoding="utf-8")

    clean_bytes = json.dumps({"results": [], "errors": []}).encode("utf-8")
    mock_proc = create_mock_process(clean_bytes, b"", returncode=0)

    scanner = BanditScanner(excluded_paths=".git,tests")
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        await scanner.scan(str(tmp_path))

        assert mock_exec.called
        args, kwargs = mock_exec.call_args
        assert args[0] == "bandit"
        assert args[1] == "-r"
        assert "-f" in args
        assert "json" in args
        assert "-q" in args
        assert "-x" in args
        assert ".git,tests" in args
        assert kwargs.get("shell") is not True
        assert kwargs.get("cwd") == str(tmp_path.resolve())
