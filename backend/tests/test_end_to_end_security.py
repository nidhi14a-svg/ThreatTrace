"""End-to-End Security Testing (specs/END_TO_END_SECURITY_TEST_SPEC.md).

Tests the complete 11-stage workflow:
1. Upload byte validation
2. Archive security validation (Zip Slip, zip bomb, corrupted archives)
3. Workspace isolation (WorkspaceManager)
4. Secure extraction
5. Scanner worker execution
6. Finding normalization
7. Secret redaction
8. Finding aggregation
9. Report generation
10. Workspace cleanup on success
11. Workspace cleanup on failure
"""

import io
import tempfile
import zipfile
from pathlib import Path
import pytest

from app.scanners.base_scanner import ScannerExecutionResult, ScannerStatus
from app.scanners.custom_rules import default_registry, register_all_custom_rules
from app.scanners.custom_rules.scanner import CustomRulesScanner
from app.scanners.worker_runner import process_and_normalize_results
from app.scanners.workspace import WorkspaceManager, WorkspaceSecurityError
from tests.test_zip_security import validate_zip_archive_security, ZipSecurityValidationError


@pytest.fixture(scope="module", autouse=True)
def setup_rules():
    """Ensure all modular custom rules are registered."""
    register_all_custom_rules(default_registry)


def create_in_memory_zip(files: dict[str, str]) -> bytes:
    """Helper to create an in-memory ZIP archive from a dict of relative paths to contents."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files.items():
            zf.writestr(filename, content)
    return buffer.getvalue()


@pytest.fixture
def temp_workspace_mgr(tmp_path):
    """Provide a WorkspaceManager backed by a temporary base directory."""
    return WorkspaceManager(base_dir=tmp_path / "workspaces")


@pytest.mark.anyio
async def test_e2e_successful_scan_workflow(temp_workspace_mgr):
    # 1. Prepare synthetic project archive
    project_files = {
        "app/main.py": "import os\ndef run(cmd):\n    os.system(cmd)\n",
        "app/config.py": "DEBUG = True\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
        "requirements.txt": "cryptography==2.8\nrequests==2.19.0\n",
    }
    zip_bytes = create_in_memory_zip(project_files)

    # 2. Validate archive security
    valid_entries = validate_zip_archive_security(zip_bytes)
    assert len(valid_entries) == 3

    # 3. Create isolated workspace
    paths = temp_workspace_mgr.create_workspace("e2e-scan-success")
    assert paths.workspace_dir.exists()

    try:
        # 4. Secure extraction
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(paths.source_dir)

        # 5. Execute scanner (Custom AST Scanner over extracted workspace)
        scanner = CustomRulesScanner(registry=default_registry, timeout=30)
        scanner_res = await scanner.scan(str(paths.source_dir))
        assert scanner_res.status in (ScannerStatus.SUCCESS, "success")
        assert len(scanner_res.findings) > 0

        # 6. Normalize, redact, aggregate report payload
        payload = process_and_normalize_results({scanner.name: scanner_res})

        assert payload["status"] == "success"
        assert payload["total_findings"] > 0
        assert "findings" in payload

        # Verify evidence redaction in the generated report
        for f in payload["findings"]:
            assert "AKIAIOSFODNN7EXAMPLE" not in f["evidence"]

    finally:
        # 7. Cleanup ephemeral workspace
        cleanup_success = temp_workspace_mgr.cleanup_workspace(paths.workspace_id)
        assert cleanup_success is True
        assert not paths.workspace_dir.exists()


@pytest.mark.anyio
async def test_e2e_partial_scanner_failure_isolation(temp_workspace_mgr):
    paths = temp_workspace_mgr.create_workspace("e2e-scan-partial")
    try:
        (paths.source_dir / "app.py").write_text("print('hello')", encoding="utf-8")

        # Mock one successful scanner and one failed scanner
        res_success = ScannerExecutionResult(
            scanner_name="custom_rules",
            status=ScannerStatus.SUCCESS,
            findings=[{"rule_id": "r1", "severity": "low", "file": "app.py"}],
        )
        res_failed = ScannerExecutionResult(
            scanner_name="semgrep",
            status=ScannerStatus.FAILED,
            findings=[],
            error="Process killed by OOM or timeout",
        )

        payload = process_and_normalize_results({
            "custom_rules": res_success,
            "semgrep": res_failed,
        })

        assert payload["status"] == "partial"
        assert payload["total_findings"] == 1
        assert payload["scanner_results"]["semgrep"]["status"] == "failed"
        assert payload["scanner_results"]["custom_rules"]["status"] == "success"

    finally:
        temp_workspace_mgr.cleanup_workspace(paths.workspace_id)
        assert not paths.workspace_dir.exists()


def test_e2e_invalid_corrupted_zip_upload_rejection():
    corrupted_bytes = b"PK\x03\x04corrupted_header_data_not_a_valid_archive"
    with pytest.raises(ZipSecurityValidationError, match="Invalid or corrupted ZIP archive"):
        validate_zip_archive_security(corrupted_bytes)


def test_e2e_zip_slip_path_traversal_rejection():
    malicious_files = {
        "../../evil.sh": "echo 'owned'",
    }
    zip_bytes = create_in_memory_zip(malicious_files)
    with pytest.raises(ZipSecurityValidationError, match="Zip Slip detected"):
        validate_zip_archive_security(zip_bytes)


def test_e2e_compression_ratio_bomb_rejection():
    # 1KB decompressing to 2MB (2000:1 ratio)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", "A" * (2 * 1024 * 1024))
    bomb_bytes = buf.getvalue()

    with pytest.raises(ZipSecurityValidationError, match="Compression ratio bomb detected"):
        validate_zip_archive_security(bomb_bytes)


@pytest.mark.anyio
async def test_e2e_clean_repository_scan_produces_zero_findings(temp_workspace_mgr):
    clean_files = {
        "app.py": "def add(a, b):\n    return a + b\n",
        "requirements.txt": "fastapi==0.115.0\npydantic==2.8.2\n",
    }
    zip_bytes = create_in_memory_zip(clean_files)
    validate_zip_archive_security(zip_bytes)

    paths = temp_workspace_mgr.create_workspace("e2e-scan-clean")
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.extractall(paths.source_dir)

        scanner = CustomRulesScanner(registry=default_registry, timeout=30)
        scanner_res = await scanner.scan(str(paths.source_dir))
        payload = process_and_normalize_results({scanner.name: scanner_res})

        assert payload["status"] == "success"
        assert payload["total_findings"] == 0

    finally:
        temp_workspace_mgr.cleanup_workspace(paths.workspace_id)
        assert not paths.workspace_dir.exists()


def test_e2e_workspace_cleanup_on_failure(temp_workspace_mgr):
    paths = temp_workspace_mgr.create_workspace("e2e-scan-failure-cleanup")
    assert paths.workspace_dir.exists()

    # Simulate an unexpected failure in processing
    try:
        raise RuntimeError("Simulated mid-scan processing error")
    except RuntimeError:
        temp_workspace_mgr.cleanup_workspace(paths.workspace_id)

    # Workspace directory must be deleted
    assert not paths.workspace_dir.exists()
