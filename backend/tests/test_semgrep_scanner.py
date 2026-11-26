import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult
from app.scanners.semgrep_scanner import SemgrepScanner


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


SAMPLE_SEMGREP_JSON = {
    "results": [
        {
            "check_id": "python.lang.security.injection.sql.sql-injection-format-string",
            "path": "app/routes.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 60},
            "extra": {
                "message": "SQL query formatted with untrusted input",
                "severity": "ERROR",
                "lines": "query = f\"SELECT * FROM users WHERE email = '{user_input}'\"",
                "metadata": {
                    "cwe": ["CWE-89: SQL Injection"],
                    "owasp": ["A03:2021 - Injection"],
                    "confidence": "HIGH",
                    "category": "security",
                },
            },
        },
        {
            "check_id": "javascript.express.security.xss.direct-response-write",
            "path": "frontend/server.js",
            "start": {"line": 88, "col": 3},
            "end": {"line": 88, "col": 40},
            "extra": {
                "message": "Unescaped output written directly to HTTP response",
                "severity": "WARNING",
                "lines": "res.send('<h1>' + req.query.name + '</h1>');",
                "metadata": {
                    "cwe": ["CWE-79: Cross-site Scripting"],
                    "confidence": "MEDIUM",
                    "subcategory": "xss",
                },
            },
        },
    ],
    "errors": [],
}


# ============================================================================
# 1. BaseScanner Interface & Initialization
# ============================================================================


def test_semgrep_scanner_satisfies_base_scanner_interface():
    """Verify SemgrepScanner satisfies the BaseScanner abstract contract."""
    scanner = SemgrepScanner()
    assert isinstance(scanner, BaseScanner)
    assert scanner.name == "semgrep"
    assert scanner.scanner_name == "semgrep"
    assert scanner.timeout_seconds == 60.0
    assert scanner.rules == "p/owasp-top-ten"
    assert scanner.max_output_bytes == 10 * 1024 * 1024


# ============================================================================
# 2. Valid Findings Execution
# ============================================================================


@pytest.mark.anyio
async def test_valid_semgrep_json_with_multiple_findings(tmp_path: Path):
    """Verify parsing of valid Semgrep JSON containing multiple findings."""
    # Create a non-empty workspace
    test_file = tmp_path / "app.py"
    test_file.write_text("print('hello')", encoding="utf-8")

    stdout_bytes = json.dumps(SAMPLE_SEMGREP_JSON).encode("utf-8")
    mock_proc = create_mock_process(stdout_bytes, b"", returncode=0)

    scanner = SemgrepScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert isinstance(result, ScannerExecutionResult)
    assert result.status == "success"
    assert result.scanner_name == "semgrep"
    assert len(result.findings) == 2
    assert result.error is None
    assert result.duration_seconds >= 0.0

    # Verify first finding attributes
    f1 = result.findings[0]
    assert f1["scanner_name"] == "semgrep"
    assert f1["rule_id"] == "python.lang.security.injection.sql.sql-injection-format-string"
    assert f1["severity"] == "ERROR"
    assert f1["raw_category"] == "security"
    assert f1["file"] == "app/routes.py"
    assert f1["line"] == 42
    assert f1["col"] == 5
    assert f1["end_line"] == 42
    assert f1["end_col"] == 60
    assert "SQL query" in f1["message"]
    assert "SELECT *" in f1["evidence"]
    assert "cwe" in f1["metadata"]

    # Verify second finding attributes
    f2 = result.findings[1]
    assert f2["rule_id"] == "javascript.express.security.xss.direct-response-write"
    assert f2["severity"] == "WARNING"
    assert f2["raw_category"] == "xss"
    assert f2["line"] == 88


# ============================================================================
# 3. Empty Findings (Clean Scan)
# ============================================================================


@pytest.mark.anyio
async def test_empty_findings_clean_scan(tmp_path: Path):
    """Verify successful execution when zero vulnerabilities are detected."""
    test_file = tmp_path / "main.py"
    test_file.write_text("print('secure code')", encoding="utf-8")

    clean_output = json.dumps({"results": [], "errors": []}).encode("utf-8")
    mock_proc = create_mock_process(clean_output, b"", returncode=0)

    scanner = SemgrepScanner()
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
    """Verify scanner handles non-JSON stdout safely."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    malformed_output = b"Internal Semgrep Fatal Error: memory allocation failure"
    mock_proc = create_mock_process(malformed_output, b"segfault trace", returncode=139)

    scanner = SemgrepScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert result.findings == []
    assert "Malformed Semgrep JSON" in result.error
    assert "segfault trace" in result.error


@pytest.mark.anyio
async def test_malformed_json_non_dict_root(tmp_path: Path):
    """Verify scanner handles JSON root that is a list instead of a dict."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    non_dict_json = json.dumps(["item1", "item2"]).encode("utf-8")
    mock_proc = create_mock_process(non_dict_json, b"", returncode=0)

    scanner = SemgrepScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "expected root JSON object" in result.error


# ============================================================================
# 5. Missing Semgrep Executable
# ============================================================================


@pytest.mark.anyio
async def test_missing_semgrep_executable_default(tmp_path: Path):
    """Verify default behavior when semgrep binary is not on PATH (status='failed')."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    scanner = SemgrepScanner(binary_path="nonexistent-semgrep-binary-xyz")
    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("binary not found")):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert result.findings == []
    assert "Semgrep executable not found" in result.error
    assert "nonexistent-semgrep-binary-xyz" in result.error


@pytest.mark.anyio
async def test_missing_semgrep_executable_skipped_policy(tmp_path: Path):
    """Verify behavior when configured to skip missing binary (status='skipped')."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    scanner = SemgrepScanner(
        binary_path="nonexistent-semgrep-binary-xyz",
        allow_skip_if_missing=True,
    )
    with patch("shutil.which", return_value=None):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "skipped"
    assert result.findings == []
    assert "executable not found" in result.error


# ============================================================================
# 6. Timeout Handling
# ============================================================================


@pytest.mark.anyio
async def test_semgrep_execution_timeout(tmp_path: Path):
    """Verify that timeout terminates the subprocess and returns status='failed'."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    mock_proc = MagicMock()
    mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_proc.kill = MagicMock()
    mock_proc.wait = AsyncMock(return_value=-9)

    scanner = SemgrepScanner(timeout_seconds=5.0)
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "timed out after 5.0 seconds" in result.error
    assert mock_proc.kill.called


# ============================================================================
# 7. Non-Zero Exit Code Handling
# ============================================================================


@pytest.mark.anyio
async def test_non_zero_exit_without_findings(tmp_path: Path):
    """Verify non-zero exit code without findings reports status='failed'."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    mock_proc = create_mock_process(b"", b"Invalid rule configuration: parse error", returncode=2)

    scanner = SemgrepScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert result.findings == []
    assert "Invalid rule configuration" in result.error


@pytest.mark.anyio
async def test_non_zero_exit_with_findings_returns_partial(tmp_path: Path):
    """Verify non-zero exit code with valid findings reports status='partial'."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    stdout_bytes = json.dumps(SAMPLE_SEMGREP_JSON).encode("utf-8")
    mock_proc = create_mock_process(stdout_bytes, b"Rule error on 1 file", returncode=1)

    scanner = SemgrepScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "partial"
    assert len(result.findings) == 2
    assert "Rule error on 1 file" in result.error


@pytest.mark.anyio
async def test_semgrep_internal_errors_in_json_returns_partial(tmp_path: Path):
    """Verify findings returned with file warnings in 'errors' report status='partial'."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    output_with_errors = {
        "results": [SAMPLE_SEMGREP_JSON["results"][0]],
        "errors": [{"message": "Syntax error in legacy.py", "spans": []}],
    }
    mock_proc = create_mock_process(json.dumps(output_with_errors).encode("utf-8"), b"", returncode=0)

    scanner = SemgrepScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "partial"
    assert len(result.findings) == 1
    assert "warnings/errors on 1 file(s)" in result.error


# ============================================================================
# 8. Missing Optional Finding Fields Handling
# ============================================================================


@pytest.mark.anyio
async def test_findings_with_missing_optional_fields(tmp_path: Path):
    """Verify finding item missing start, end, extra, and metadata parses gracefully."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    minimal_output = {
        "results": [
            {
                "check_id": "minimal-rule",
                "path": "minimal.py",
            }
        ],
        "errors": [],
    }
    mock_proc = create_mock_process(json.dumps(minimal_output).encode("utf-8"), b"", returncode=0)

    scanner = SemgrepScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "success"
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["rule_id"] == "minimal-rule"
    assert f["file"] == "minimal.py"
    assert f["line"] is None
    assert f["col"] is None
    assert f["end_line"] is None
    assert f["end_col"] is None
    assert f["severity"] == "WARNING"
    assert f["raw_category"] is None
    assert f["evidence"] == ""
    assert f["metadata"] == {}


# ============================================================================
# 9. Path Security & Traversal Prevention
# ============================================================================


@pytest.mark.anyio
async def test_correct_relative_path_handling(tmp_path: Path):
    """Verify paths inside workspace are properly normalized to POSIX relative paths."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    # Absolute path matching workspace
    abs_inside = str(tmp_path / "sub" / "module.py")

    path_test_output = {
        "results": [
            {"check_id": "r1", "path": "src/app.py"},
            {"check_id": "r2", "path": abs_inside},
            {"check_id": "r3", "path": "./config/settings.json"},
        ],
        "errors": [],
    }
    mock_proc = create_mock_process(json.dumps(path_test_output).encode("utf-8"), b"", returncode=0)

    scanner = SemgrepScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "success"
    assert len(result.findings) == 3
    assert result.findings[0]["file"] == "src/app.py"
    assert result.findings[1]["file"] == "sub/module.py"
    assert result.findings[2]["file"] == "config/settings.json"


@pytest.mark.anyio
async def test_rejection_of_paths_outside_workspace(tmp_path: Path):
    """Verify path traversal outside workspace is safely rejected."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    traversal_output = {
        "results": [
            {"check_id": "traversal-1", "path": "../../etc/shadow"},
            {"check_id": "traversal-2", "path": "/etc/passwd"},
        ],
        "errors": [],
    }
    mock_proc = create_mock_process(json.dumps(traversal_output).encode("utf-8"), b"", returncode=0)

    scanner = SemgrepScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "success"
    assert len(result.findings) == 2
    assert result.findings[0]["file"] == "[REJECTED_OUTSIDE_WORKSPACE]"
    assert result.findings[1]["file"] == "[REJECTED_OUTSIDE_WORKSPACE]"
    assert "/etc" not in result.findings[0]["file"]


# ============================================================================
# 10. Safe and Bounded Error Messages & Output Ceilings
# ============================================================================


@pytest.mark.anyio
async def test_safe_and_bounded_error_messages(tmp_path: Path):
    """Verify ANSI escape codes are stripped and error length is capped."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    noisy_stderr = b"\x1b[31mError:\x1b[0m Fatal crash in parser.\n" + (b"long trace line\n" * 100)
    mock_proc = create_mock_process(b"", noisy_stderr, returncode=1)

    scanner = SemgrepScanner()
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "\x1b[" not in result.error  # No ANSI codes
    assert len(result.error) <= 550  # Bounded length


@pytest.mark.anyio
async def test_bounded_stdout_output_handling(tmp_path: Path):
    """Verify execution fails safely when output buffer exceeds memory ceiling."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    huge_stdout = b"A" * 1500  # Exceeds max_output_bytes=1000
    mock_proc = create_mock_process(huge_stdout, b"", returncode=0)

    scanner = SemgrepScanner(max_output_bytes=1000)
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await scanner.scan(str(tmp_path))

    assert result.status == "failed"
    assert "exceeded maximum output limit" in result.error


# ============================================================================
# 11. Workspace Validation & Empty Workspace Handling
# ============================================================================


@pytest.mark.anyio
async def test_workspace_validation_non_existent():
    """Verify non-existent workspace path returns status='skipped' with error=None."""
    scanner = SemgrepScanner()
    result = await scanner.scan("/nonexistent/directory/xyz123")
    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None


@pytest.mark.anyio
async def test_workspace_validation_file_not_dir(tmp_path: Path):
    """Verify workspace path pointing to a file returns status='failed'."""
    file_path = tmp_path / "file.txt"
    file_path.write_text("content", encoding="utf-8")

    scanner = SemgrepScanner()
    result = await scanner.scan(str(file_path))
    assert result.status == "failed"
    assert "is not a directory" in result.error


@pytest.mark.anyio
async def test_workspace_validation_empty_string():
    """Verify empty string workspace returns status='failed'."""
    scanner = SemgrepScanner()
    result = await scanner.scan("")
    assert result.status == "failed"
    assert "cannot be empty" in result.error


@pytest.mark.anyio
async def test_empty_workspace_returns_skipped(tmp_path: Path):
    """Verify empty directory with zero files returns status='skipped'."""
    scanner = SemgrepScanner()
    result = await scanner.scan(str(tmp_path))
    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None


# ============================================================================
# 12. Safe Subprocess Arguments (No shell=True)
# ============================================================================


@pytest.mark.anyio
async def test_safe_subprocess_arguments_invoked(tmp_path: Path):
    """Verify command is passed as an argument list and shell=True is not used."""
    test_file = tmp_path / "main.py"
    test_file.write_text("code", encoding="utf-8")

    stdout_bytes = json.dumps({"results": [], "errors": []}).encode("utf-8")
    mock_proc = create_mock_process(stdout_bytes, b"", returncode=0)

    scanner = SemgrepScanner(rules="p/ci")
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        await scanner.scan(str(tmp_path))

        assert mock_exec.called
        args, kwargs = mock_exec.call_args
        # Verify passed as list
        assert args[0] == "semgrep"
        assert args[1] == "scan"
        assert "--json" in args
        assert "--config" in args
        assert "p/ci" in args
        assert "--metrics=off" in args
        assert "--disable-version-check" in args
        # Verify shell is NOT in kwargs or is False
        assert kwargs.get("shell") is not True
        assert kwargs.get("cwd") == str(tmp_path.resolve())
