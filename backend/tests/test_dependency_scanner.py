import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult
from app.scanners.dependency_scanner import DependencyScanner


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


SAMPLE_OSV_SCANNER_JSON = {
    "results": [
        {
            "source": {
                "path": "/workspace/requirements.txt",
                "type": "lockfile",
            },
            "packages": [
                {
                    "package": {
                        "name": "jinja2",
                        "version": "2.11.2",
                        "ecosystem": "PyPI",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-g3rq-g295-4838",
                            "summary": "Jinja2 vulnerable to ReDoS",
                            "details": "In Jinja2 before 2.11.3, an attacker can cause a denial of service via regex exponential blowup.",
                            "aliases": ["CVE-2020-28493"],
                            "severity": [
                                {
                                    "type": "CVSS_V3",
                                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                }
                            ],
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "2.11.3"},
                                            ],
                                        }
                                    ]
                                }
                            ],
                            "database_specific": {
                                "severity": "HIGH",
                            },
                        }
                    ],
                }
            ],
        },
        {
            "source": {
                "path": "/workspace/frontend/package-lock.json",
                "type": "lockfile",
            },
            "packages": [
                {
                    "package": {
                        "name": "lodash",
                        "version": "4.17.15",
                        "ecosystem": "npm",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-p6mc-m468-83gw",
                            "summary": "Prototype Pollution in lodash",
                            "details": "Lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution.",
                            "aliases": ["CVE-2020-8203"],
                            "severity": [
                                {
                                    "type": "CVSS_V3",
                                    "score": 9.8,
                                }
                            ],
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "4.17.21"},
                                            ],
                                        }
                                    ]
                                }
                            ],
                            "database_specific": {
                                "severity": "CRITICAL",
                            },
                        }
                    ],
                }
            ],
        },
    ]
}


# ============================================================================
# 1. BaseScanner Interface & Initialization
# ============================================================================


def test_dependency_scanner_satisfies_base_scanner_interface():
    """Verify DependencyScanner satisfies the BaseScanner abstract contract."""
    scanner = DependencyScanner()
    assert isinstance(scanner, BaseScanner)
    assert scanner.name == "dependency"
    assert scanner.scanner_name == "dependency"
    assert callable(getattr(scanner, "scan", None))
    assert asyncio.iscoroutinefunction(scanner.scan)


def test_dependency_scanner_initialization_defaults():
    """Verify default initialization values."""
    scanner = DependencyScanner()
    assert scanner.binary_path == "osv-scanner"
    assert scanner.timeout_seconds == 60.0
    assert scanner.max_output_bytes == 10 * 1024 * 1024
    assert scanner.allow_skip_if_missing is False
    assert scanner.offline is False


def test_dependency_scanner_initialization_custom_and_env(monkeypatch):
    """Verify initialization respects custom parameters and environment variables."""
    monkeypatch.setenv("OSV_SCANNER_BINARY_PATH", "/custom/bin/osv-scanner")
    monkeypatch.setenv("OSV_SCANNER_TIMEOUT_SECONDS", "120.0")
    monkeypatch.setenv("OSV_SCANNER_MAX_OUTPUT_BYTES", "5242880")
    monkeypatch.setenv("OSV_SCANNER_OFFLINE", "true")

    scanner = DependencyScanner()
    assert scanner.binary_path == "/custom/bin/osv-scanner"
    assert scanner.timeout_seconds == 120.0
    assert scanner.max_output_bytes == 5242880
    assert scanner.offline is True


def test_dependency_scanner_is_available():
    """Verify is_available checks PATH using shutil.which."""
    scanner = DependencyScanner(binary_path="osv-scanner")
    with patch("shutil.which", return_value="/usr/local/bin/osv-scanner"):
        assert scanner.is_available() is True

    with patch("shutil.which", return_value=None):
        assert scanner.is_available() is False


# ============================================================================
# 2. Workspace Validation & Fast Skipping
# ============================================================================


@pytest.mark.anyio
async def test_scan_empty_workspace_string_returns_failed():
    """Verify empty or whitespace-only workspace path returns 'failed'."""
    scanner = DependencyScanner()
    result = await scanner.scan("")
    assert result.status == "failed"
    assert "Workspace path is required" in result.error

    result = await scanner.scan("   ")
    assert result.status == "failed"
    assert "Workspace path is required" in result.error


@pytest.mark.anyio
async def test_scan_nonexistent_workspace_returns_skipped(tmp_path):
    """Verify non-existent workspace returns 'skipped' with no error."""
    scanner = DependencyScanner()
    nonexistent = tmp_path / "does_not_exist"
    result = await scanner.scan(str(nonexistent))
    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None


@pytest.mark.anyio
async def test_scan_workspace_file_instead_of_dir_returns_failed(tmp_path):
    """Verify workspace pointing to a file returns 'failed'."""
    scanner = DependencyScanner()
    file_path = tmp_path / "regular_file.txt"
    file_path.write_text("just a file")

    result = await scanner.scan(str(file_path))
    assert result.status == "failed"
    assert "not a directory" in result.error


@pytest.mark.anyio
async def test_scan_empty_workspace_dir_returns_skipped(tmp_path):
    """Verify empty workspace directory returns 'skipped' with zero findings."""
    scanner = DependencyScanner()
    empty_dir = tmp_path / "empty_project"
    empty_dir.mkdir()

    result = await scanner.scan(str(empty_dir))
    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None


@pytest.mark.anyio
async def test_scan_workspace_without_manifest_files_returns_skipped(tmp_path):
    """Verify workspace without any supported dependency manifests is skipped cleanly."""
    scanner = DependencyScanner()
    project_dir = tmp_path / "python_code_only"
    project_dir.mkdir()
    (project_dir / "main.py").write_text("print('hello world')")
    (project_dir / "utils.py").write_text("x = 1")
    (project_dir / "README.md").write_text("# Project")

    result = await scanner.scan(str(project_dir))
    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None


@pytest.mark.parametrize(
    "manifest_name",
    [
        "requirements.txt",
        "requirements-dev.txt",
        "Pipfile.lock",
        "poetry.lock",
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
    ],
)
def test_manifest_detection_identifies_all_ecosystem_files(tmp_path, manifest_name):
    """Verify _has_manifest_files identifies all supported ecosystem manifests."""
    scanner = DependencyScanner()
    project_dir = tmp_path / f"test_{manifest_name}"
    project_dir.mkdir()
    (project_dir / manifest_name).write_text("content")

    assert scanner._has_manifest_files(project_dir) is True


# ============================================================================
# 3. Missing Binary Handling
# ============================================================================


@pytest.mark.anyio
async def test_scan_missing_binary_fails_by_default(tmp_path):
    """Verify missing OSV-Scanner executable returns 'failed' by default."""
    scanner = DependencyScanner(allow_skip_if_missing=False)
    project_dir = tmp_path / "app"
    project_dir.mkdir()
    (project_dir / "requirements.txt").write_text("requests==2.25.1")

    with patch.object(scanner, "is_available", return_value=False):
        result = await scanner.scan(str(project_dir))
        assert result.status == "failed"
        assert "not found on PATH" in result.error
        assert result.findings == []


@pytest.mark.anyio
async def test_scan_missing_binary_skipped_when_configured(tmp_path):
    """Verify missing OSV-Scanner returns 'skipped' when allow_skip_if_missing=True."""
    scanner = DependencyScanner(allow_skip_if_missing=True)
    project_dir = tmp_path / "app"
    project_dir.mkdir()
    (project_dir / "requirements.txt").write_text("requests==2.25.1")

    with patch.object(scanner, "is_available", return_value=False):
        result = await scanner.scan(str(project_dir))
        assert result.status == "skipped"
        assert result.error is None
        assert result.findings == []


# ============================================================================
# 4. Successful Scan & Finding Normalization
# ============================================================================


@pytest.mark.anyio
async def test_scan_successful_vulnerability_parsing(tmp_path):
    """Verify complete OSV-Scanner execution and parsing of findings."""
    scanner = DependencyScanner()
    workspace_dir = tmp_path / "vuln_app"
    workspace_dir.mkdir()
    (workspace_dir / "requirements.txt").write_text("jinja2==2.11.2")
    frontend_dir = workspace_dir / "frontend"
    frontend_dir.mkdir()
    (frontend_dir / "package-lock.json").write_text("{}")

    # Update sample paths to match workspace_dir
    sample_json = json.loads(json.dumps(SAMPLE_OSV_SCANNER_JSON))
    sample_json["results"][0]["source"]["path"] = str(workspace_dir / "requirements.txt")
    sample_json["results"][1]["source"]["path"] = str(frontend_dir / "package-lock.json")

    mock_proc = create_mock_process(
        stdout_bytes=json.dumps(sample_json).encode("utf-8"),
        stderr_bytes=b"",
        returncode=1,  # OSV-Scanner returns 1 when vulnerabilities are found
    )

    with patch.object(scanner, "is_available", return_value=True), patch(
        "asyncio.create_subprocess_exec", return_value=mock_proc
    ) as mock_exec:
        result = await scanner.scan(str(workspace_dir))

        # Check command invocation
        mock_exec.assert_called_once()
        args = mock_exec.call_args[0]
        assert args[0] == "osv-scanner"
        assert args[1] == "--json"
        assert args[2] == "-r"
        assert args[3] == str(workspace_dir.resolve())

        # Check status and findings
        assert result.status == "success"
        assert result.scanner_name == "dependency"
        assert len(result.findings) == 2
        assert result.error is None

        # Inspect finding 1 (Python requirements.txt)
        f1 = result.findings[0]
        assert f1["scanner_name"] == "dependency"
        assert f1["rule_id"] == "GHSA-g3rq-g295-4838"
        assert f1["title"] == "Jinja2 vulnerable to ReDoS"
        assert f1["severity"] == "high"
        assert f1["file"] == "requirements.txt"
        assert f1["line"] is None
        assert f1["confidence"] == "medium"  # unpinned manifest
        assert f1["raw_category"] == "dependency_vulnerability"
        assert f1["package_name"] == "jinja2"
        assert f1["package_version"] == "2.11.2"
        assert f1["package_ecosystem"] == "PyPI"
        assert "CVE-2020-28493" in f1["aliases"]
        assert "2.11.3" in f1["fixed_versions"]
        assert "Jinja2 vulnerable to ReDoS" in f1["evidence"]
        assert "Fixed in: 2.11.3" in f1["evidence"]
        assert f1["advisory_url"] == "https://osv.dev/vulnerability/GHSA-g3rq-g295-4838"

        # Inspect finding 2 (Node package-lock.json)
        f2 = result.findings[1]
        assert f2["scanner_name"] == "dependency"
        assert f2["rule_id"] == "GHSA-p6mc-m468-83gw"
        assert f2["title"] == "Prototype Pollution in lodash"
        assert f2["severity"] == "critical"
        assert f2["file"] == "frontend/package-lock.json"
        assert f2["line"] is None
        assert f2["confidence"] == "high"  # exact lockfile
        assert f2["raw_category"] == "dependency_vulnerability"
        assert f2["package_name"] == "lodash"
        assert f2["package_version"] == "4.17.15"
        assert f2["package_ecosystem"] == "npm"
        assert "CVE-2020-8203" in f2["aliases"]
        assert "4.17.21" in f2["fixed_versions"]


@pytest.mark.anyio
async def test_scan_clean_workspace_zero_vulnerabilities(tmp_path):
    """Verify clean scan with exit code 0 returns success and empty findings."""
    scanner = DependencyScanner()
    workspace_dir = tmp_path / "clean_app"
    workspace_dir.mkdir()
    (workspace_dir / "requirements.txt").write_text("clean-package==1.0.0")

    mock_proc = create_mock_process(
        stdout_bytes=b'{"results": []}',
        stderr_bytes=b"",
        returncode=0,
    )

    with patch.object(scanner, "is_available", return_value=True), patch(
        "asyncio.create_subprocess_exec", return_value=mock_proc
    ):
        result = await scanner.scan(str(workspace_dir))
        assert result.status == "success"
        assert result.findings == []
        assert result.error is None


@pytest.mark.anyio
async def test_scan_offline_flag_included_when_configured(tmp_path):
    """Verify --offline flag is passed when offline=True."""
    scanner = DependencyScanner(offline=True)
    workspace_dir = tmp_path / "offline_app"
    workspace_dir.mkdir()
    (workspace_dir / "requirements.txt").write_text("requests==2.25.1")

    mock_proc = create_mock_process(
        stdout_bytes=b'{"results": []}',
        stderr_bytes=b"",
        returncode=0,
    )

    with patch.object(scanner, "is_available", return_value=True), patch(
        "asyncio.create_subprocess_exec", return_value=mock_proc
    ) as mock_exec:
        await scanner.scan(str(workspace_dir))
        args = mock_exec.call_args[0]
        assert "--offline" in args


# ============================================================================
# 5. Severity & Confidence Derivation
# ============================================================================


def test_severity_derivation_from_cvss_scores():
    """Verify severity calculation from numeric CVSS v3 scores."""
    scanner = DependencyScanner()

    # Critical: >= 9.0
    assert scanner._extract_severity({"severity": [{"score": 9.8}]}) == "critical"
    assert scanner._extract_severity({"severity": [{"score": "9.0"}]}) == "critical"

    # High: 7.0 - 8.9
    assert scanner._extract_severity({"severity": [{"score": 7.5}]}) == "high"
    assert scanner._extract_severity({"severity": [{"score": "8.9"}]}) == "high"

    # Medium: 4.0 - 6.9
    assert scanner._extract_severity({"severity": [{"score": 5.4}]}) == "medium"
    assert scanner._extract_severity({"severity": [{"score": "4.0"}]}) == "medium"

    # Low: < 4.0
    assert scanner._extract_severity({"severity": [{"score": 3.1}]}) == "low"
    assert scanner._extract_severity({"severity": [{"score": "1.5"}]}) == "low"


def test_severity_derivation_from_database_specific():
    """Verify severity calculation from database_specific strings."""
    scanner = DependencyScanner()

    assert scanner._extract_severity({"database_specific": {"severity": "CRITICAL"}}) == "critical"
    assert scanner._extract_severity({"database_specific": {"severity": "HIGH"}}) == "high"
    assert scanner._extract_severity({"database_specific": {"severity": "MODERATE"}}) == "medium"
    assert scanner._extract_severity({"database_specific": {"severity": "LOW"}}) == "low"
    assert scanner._extract_severity({}) == "medium"  # Fallback default


def test_confidence_derivation_lockfile_vs_manifest():
    """Verify confidence is 'high' for deterministic lockfiles, 'medium' for manifests."""
    scanner = DependencyScanner()

    # Lockfiles -> high
    assert scanner._determine_confidence("package-lock.json") == "high"
    assert scanner._determine_confidence("frontend/yarn.lock") == "high"
    assert scanner._determine_confidence("Pipfile.lock") == "high"
    assert scanner._determine_confidence("poetry.lock") == "high"
    assert scanner._determine_confidence("Cargo.lock") == "high"
    assert scanner._determine_confidence("go.sum") == "high"

    # Manifests -> medium
    assert scanner._determine_confidence("requirements.txt") == "medium"
    assert scanner._determine_confidence("package.json") == "medium"
    assert scanner._determine_confidence("pyproject.toml") == "medium"
    assert scanner._determine_confidence("pom.xml") == "medium"
    assert scanner._determine_confidence("go.mod") == "medium"


# ============================================================================
# 6. Error & Failure Handling
# ============================================================================


@pytest.mark.anyio
async def test_scan_subprocess_timeout_returns_failed(tmp_path):
    """Verify subprocess execution timeout returns 'failed'."""
    scanner = DependencyScanner(timeout_seconds=0.01)
    workspace_dir = tmp_path / "timeout_app"
    workspace_dir.mkdir()
    (workspace_dir / "requirements.txt").write_text("slow==1.0.0")

    async def slow_communicate():
        await asyncio.sleep(0.5)
        return (b"{}", b"")

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.communicate = slow_communicate
    mock_proc.kill = MagicMock()
    mock_proc.wait = AsyncMock(return_value=0)

    with patch.object(scanner, "is_available", return_value=True), patch(
        "asyncio.create_subprocess_exec", return_value=mock_proc
    ):
        result = await scanner.scan(str(workspace_dir))
        assert result.status == "failed"
        assert "timed out" in result.error


@pytest.mark.anyio
async def test_scan_malformed_json_returns_failed(tmp_path):
    """Verify unparseable scanner output returns 'failed'."""
    scanner = DependencyScanner()
    workspace_dir = tmp_path / "bad_json_app"
    workspace_dir.mkdir()
    (workspace_dir / "requirements.txt").write_text("bad==1.0.0")

    mock_proc = create_mock_process(
        stdout_bytes=b"This is not JSON at all!",
        stderr_bytes=b"Some CLI warning",
        returncode=1,
    )

    with patch.object(scanner, "is_available", return_value=True), patch(
        "asyncio.create_subprocess_exec", return_value=mock_proc
    ):
        result = await scanner.scan(str(workspace_dir))
        assert result.status == "failed"
        assert result.findings == []


@pytest.mark.anyio
async def test_scan_exit_code_2_returns_failed(tmp_path):
    """Verify process exit code >= 2 returns 'failed'."""
    scanner = DependencyScanner()
    workspace_dir = tmp_path / "fatal_app"
    workspace_dir.mkdir()
    (workspace_dir / "requirements.txt").write_text("fatal==1.0.0")

    mock_proc = create_mock_process(
        stdout_bytes=b"",
        stderr_bytes=b"Fatal error: invalid flag --unknown",
        returncode=2,
    )

    with patch.object(scanner, "is_available", return_value=True), patch(
        "asyncio.create_subprocess_exec", return_value=mock_proc
    ):
        result = await scanner.scan(str(workspace_dir))
        assert result.status == "failed"
        assert "Fatal error" in result.error


# ============================================================================
# 7. Path Traversal & Evidence Bounding
# ============================================================================


def test_path_sanitization_rejects_directory_traversal(tmp_path):
    """Verify manifest paths attempting directory traversal are rejected."""
    scanner = DependencyScanner()
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    # Normal relative path
    assert scanner._sanitize_path("requirements.txt", workspace) == "requirements.txt"
    assert scanner._sanitize_path("frontend/package.json", workspace) == "frontend/package.json"

    # Absolute path inside workspace
    inside = workspace / "backend" / "requirements.txt"
    assert scanner._sanitize_path(str(inside), workspace) == "backend/requirements.txt"

    # Traversal attempting to escape workspace
    assert scanner._sanitize_path("../../etc/passwd", workspace) == "[REJECTED_OUTSIDE_WORKSPACE]"
    assert scanner._sanitize_path(str(tmp_path / "outside.txt"), workspace) == "[REJECTED_OUTSIDE_WORKSPACE]"


def test_evidence_bounding_does_not_exceed_1000_chars():
    """Verify constructed evidence strings never exceed the 1,000 char bounding limit."""
    scanner = DependencyScanner()
    long_title = "A" * 1500
    evidence = scanner._build_evidence(
        pkg_name="huge-package",
        pkg_version="1.0.0",
        manifest_path="requirements.txt",
        vuln_id="CVE-2023-99999",
        title=long_title,
        fixed_versions=["2.0.0", "3.0.0"],
    )
    assert len(evidence) <= 1000
    assert evidence.endswith("...")
