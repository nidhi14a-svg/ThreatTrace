"""Tests for Docker, Compose, and DevOps security infrastructure.

Validates:
- 4-container service segregation (frontend, backend, mongodb, scanner)
- Unprivileged scanner execution (UID 10001, read-only rootfs, dropped capabilities)
- Network isolation (air-gapped scanner-net and db-net, zero direct DB access from scanner)
- Resource limit ceilings (CPU, memory, swap disabled, PIDs limits)
- Secret quarantine (zero credentials passed to scanner worker)
- Ephemeral workspace management and path traversal defenses
- Automated retention and cleanup script behavior
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.scanners.workspace import (
    WorkspaceManager,
    WorkspacePaths,
    WorkspaceSecurityError,
)
from scripts.cleanup_workspaces import (
    CleanupReport,
    clean_uploads,
    clean_workspaces,
    cleanup_all,
    is_safe_child,
)

COMPOSE_FILE = ROOT_DIR / "docker-compose.yml"
SCANNER_DOCKERFILE = ROOT_DIR / "backend" / "Dockerfile.scanner"
ENV_EXAMPLE = ROOT_DIR / ".env.example"
GITIGNORE = ROOT_DIR / ".gitignore"


@pytest.fixture
def compose_config() -> dict:
    """Load and parse docker-compose.yml."""
    assert COMPOSE_FILE.exists(), f"docker-compose.yml not found at {COMPOSE_FILE}"
    with open(COMPOSE_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class TestDockerComposeArchitecture:
    """Test 4-container layout, networking, resource limits, and privilege drop."""

    def test_services_contain_exact_four_containers(self, compose_config: dict) -> None:
        """Verify the architecture separates exactly 4 dedicated services."""
        services = compose_config.get("services", {})
        assert set(services.keys()) == {"frontend", "backend", "mongodb", "scanner"}, (
            f"Expected exactly 4 services, got: {list(services.keys())}"
        )

    def test_scanner_worker_security_profile(self, compose_config: dict) -> None:
        """Verify dedicated scanner container has hardened non-root and read-only settings."""
        scanner = compose_config["services"]["scanner"]

        # Non-root user
        assert scanner.get("user") == "10001:10001", "Scanner must execute as non-root UID 10001:10001"

        # Read-only root filesystem
        assert scanner.get("read_only") is True, "Scanner rootfs must be mounted read-only"

        # Tmpfs for writable scratch space
        tmpfs = scanner.get("tmpfs", [])
        assert any("/tmp" in entry for entry in tmpfs), "Scanner must provide tmpfs for /tmp"

        # Dropped capabilities
        cap_drop = scanner.get("cap_drop", [])
        assert "ALL" in cap_drop, "Scanner must drop ALL Linux capabilities"

        # No new privileges
        security_opt = scanner.get("security_opt", [])
        assert "no-new-privileges:true" in security_opt, "Scanner must enforce no-new-privileges"

    def test_scanner_worker_resource_limits(self, compose_config: dict) -> None:
        """Verify scanner container enforces strict CPU, RAM, swap, and PID limits."""
        scanner = compose_config["services"]["scanner"]

        # CPU limit: 2.0 cores max
        assert float(scanner.get("cpus", 0)) <= 2.0
        # Memory limit: 1.5 GB (1536M) max
        mem_limit = scanner.get("mem_limit", "")
        assert mem_limit in ("1536m", "1536M", "1.5g", "1.5G")

        # Swap disabled (memswap_limit == mem_limit)
        memswap = scanner.get("memswap_limit", "")
        assert memswap == mem_limit, "Memory swap must equal memory limit to disable swap thrashing"

        # PIDs limit: max 100
        assert int(scanner.get("pids_limit", 0)) <= 100

        # Deploy limits
        deploy_limits = scanner.get("deploy", {}).get("resources", {}).get("limits", {})
        assert deploy_limits.get("cpus") == "2.0"
        assert deploy_limits.get("memory") == "1536M"
        assert int(deploy_limits.get("pids", 0)) <= 100

    def test_backend_and_db_resource_limits(self, compose_config: dict) -> None:
        """Verify backend and database services are also bounded."""
        backend = compose_config["services"]["backend"]
        assert float(backend.get("cpus", 0)) <= 1.5
        assert backend.get("mem_limit") in ("1024m", "1024M", "1g", "1G")

        mongodb = compose_config["services"]["mongodb"]
        assert float(mongodb.get("cpus", 0)) <= 1.0
        assert mongodb.get("mem_limit") in ("1024m", "1024M", "1g", "1G")

    def test_network_isolation_and_airgap(self, compose_config: dict) -> None:
        """Verify networks enforce strict segregation: scanner has no DB access."""
        networks = compose_config.get("networks", {})
        assert "app-net" in networks
        assert "db-net" in networks
        assert "scanner-net" in networks

        # db-net and scanner-net must be internal (no direct internet egress)
        assert networks["db-net"].get("internal") is True
        assert networks["scanner-net"].get("internal") is True

        scanner = compose_config["services"]["scanner"]
        mongodb = compose_config["services"]["mongodb"]
        backend = compose_config["services"]["backend"]

        # Scanner must be on scanner-net ONLY
        assert scanner.get("networks") == ["scanner-net"]
        # MongoDB must be on db-net ONLY
        assert mongodb.get("networks") == ["db-net"]
        # Backend bridges app-net, db-net, and scanner-net
        assert set(backend.get("networks", [])) == {"app-net", "db-net", "scanner-net"}

    def test_secret_quarantine_in_scanner(self, compose_config: dict) -> None:
        """Verify scanner container receives zero database credentials or AI API keys."""
        scanner_env = compose_config["services"]["scanner"].get("environment", [])
        scanner_env_str = " ".join(str(e) for e in scanner_env)

        assert "MONGODB_URI" not in scanner_env_str
        assert "AI_API_KEY" not in scanner_env_str
        assert "JWT_SECRET" not in scanner_env_str
        assert "DATABASE_NAME" not in scanner_env_str

    def test_shared_workspace_volume_mounts(self, compose_config: dict) -> None:
        """Verify scanner_workspaces volume is shared between backend and scanner."""
        volumes = compose_config.get("volumes", {})
        assert "scanner_workspaces" in volumes
        assert "mongodb_data" in volumes

        backend_vols = compose_config["services"]["backend"].get("volumes", [])
        scanner_vols = compose_config["services"]["scanner"].get("volumes", [])

        assert any("scanner_workspaces:/tmp/thread-trace/workspaces" in v for v in backend_vols)
        assert any("scanner_workspaces:/tmp/thread-trace/workspaces" in v for v in scanner_vols)


class TestScannerDockerfile:
    """Test Dockerfile.scanner directives and build constraints."""

    def test_dockerfile_scanner_exists(self) -> None:
        """Verify Dockerfile.scanner is present."""
        assert SCANNER_DOCKERFILE.exists()

    def test_dockerfile_scanner_security_directives(self) -> None:
        """Verify Dockerfile.scanner contains non-root user, pinned tools, and safe defaults."""
        content = SCANNER_DOCKERFILE.read_text(encoding="utf-8")

        # Base image
        assert "python:3.12-slim" in content

        # Non-root user creation
        assert "10001" in content
        assert "USER 10001:10001" in content

        # Pinned static tools
        assert "gitleaks" in content
        assert "8.21.2" in content
        assert "osv-scanner" in content
        assert "1.9.0" in content

        # Entrypoint uses worker_runner
        assert "app.scanners.worker_runner" in content


class TestWorkspaceManager:
    """Test ephemeral workspace management and path traversal defenses."""

    @pytest.fixture
    def temp_base_dir(self, tmp_path: Path) -> Path:
        """Create a temporary workspaces base directory."""
        ws_base = tmp_path / "workspaces"
        ws_base.mkdir(parents=True, exist_ok=True)
        return ws_base

    def test_create_workspace_structure(self, temp_base_dir: Path) -> None:
        """Verify create_workspace creates source and output subdirectories."""
        wm = WorkspaceManager(base_dir=temp_base_dir)
        paths = wm.create_workspace("scan-12345678")

        assert paths.workspace_id == "scan-12345678"
        assert paths.source_dir.exists()
        assert paths.output_dir.exists()
        assert paths.workspace_dir.is_relative_to(temp_base_dir)

    def test_path_traversal_prevention_in_workspace_id(self, temp_base_dir: Path) -> None:
        """Verify invalid or malicious scan IDs are rejected."""
        wm = WorkspaceManager(base_dir=temp_base_dir)

        malicious_ids = [
            "../etc/passwd",
            "../../breakout",
            "id/with/slashes",
            "id\\with\\backslashes",
            "short",  # < 8 chars
            "",
            "   ",
            "id with spaces!",
        ]

        for bad_id in malicious_ids:
            with pytest.raises(WorkspaceSecurityError):
                wm.create_workspace(bad_id)

    def test_cleanup_workspace(self, temp_base_dir: Path) -> None:
        """Verify cleanup_workspace removes directory safely."""
        wm = WorkspaceManager(base_dir=temp_base_dir)
        paths = wm.create_workspace()
        assert paths.workspace_dir.exists()

        success = wm.cleanup_workspace(paths.workspace_id)
        assert success is True
        assert not paths.workspace_dir.exists()

    def test_cleanup_expired_workspaces(self, temp_base_dir: Path) -> None:
        """Verify TTL expiration deletes stale workspaces and retains fresh ones."""
        wm = WorkspaceManager(base_dir=temp_base_dir, ttl_seconds=10)

        # Fresh workspace
        fresh_paths = wm.create_workspace("fresh-workspace-1")

        # Stale workspace with artificial past mtime
        stale_paths = wm.create_workspace("stale-workspace-1")
        past_time = time.time() - 200
        os.utime(stale_paths.workspace_dir, (past_time, past_time))

        deleted = wm.cleanup_expired_workspaces(ttl_seconds=10)
        assert deleted == 1
        assert not stale_paths.workspace_dir.exists()
        assert fresh_paths.workspace_dir.exists()

    def test_context_manager_auto_cleanup(self, temp_base_dir: Path) -> None:
        """Verify isolated_workspace automatically cleans up on exit."""
        wm = WorkspaceManager(base_dir=temp_base_dir)

        ws_dir = None
        with wm.isolated_workspace() as paths:
            ws_dir = paths.workspace_dir
            assert ws_dir.exists()
            assert paths.source_dir.exists()

        assert not ws_dir.exists()


class TestCleanupScript:
    """Test cleanup_workspaces.py utility functions."""

    @pytest.fixture
    def setup_cleanup_dirs(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create test workspace and upload directories with test files."""
        ws_dir = tmp_path / "workspaces"
        up_dir = tmp_path / "uploads"
        ws_dir.mkdir(parents=True, exist_ok=True)
        up_dir.mkdir(parents=True, exist_ok=True)
        return ws_dir, up_dir

    def test_is_safe_child(self, setup_cleanup_dirs: tuple[Path, Path]) -> None:
        """Verify safe child check distinguishes children from breakout paths."""
        ws_dir, _ = setup_cleanup_dirs
        child = ws_dir / "valid-child"
        child.mkdir()

        assert is_safe_child(child, ws_dir) is True
        assert is_safe_child(ws_dir, ws_dir) is False
        assert is_safe_child(ws_dir.parent, ws_dir) is False

    def test_clean_workspaces_and_uploads(self, setup_cleanup_dirs: tuple[Path, Path]) -> None:
        """Verify clean_workspaces and clean_uploads delete expired items."""
        ws_dir, up_dir = setup_cleanup_dirs

        # Create expired workspace
        expired_ws = ws_dir / "expired-ws-12345"
        expired_ws.mkdir()
        (expired_ws / "test.txt").write_text("sample content")
        past_time = time.time() - 500
        os.utime(expired_ws, (past_time, past_time))

        # Create fresh workspace
        fresh_ws = ws_dir / "fresh-ws-12345"
        fresh_ws.mkdir()

        # Create expired upload ZIP
        expired_zip = up_dir / "expired.zip"
        expired_zip.write_text("PK...")
        os.utime(expired_zip, (past_time, past_time))

        # Create fresh upload ZIP
        fresh_zip = up_dir / "fresh.zip"
        fresh_zip.write_text("PK...")

        report = cleanup_all(
            workspace_dir=ws_dir,
            upload_dir=up_dir,
            workspace_ttl=100,
            upload_ttl=100,
            dry_run=False,
        )

        assert report.workspaces_removed == 1
        assert report.uploads_removed == 1
        assert not expired_ws.exists()
        assert not expired_zip.exists()
        assert fresh_ws.exists()
        assert fresh_zip.exists()

    def test_dry_run_mode(self, setup_cleanup_dirs: tuple[Path, Path]) -> None:
        """Verify dry run calculates removed count without deleting files."""
        ws_dir, up_dir = setup_cleanup_dirs

        expired_ws = ws_dir / "expired-ws-99999"
        expired_ws.mkdir()
        past_time = time.time() - 500
        os.utime(expired_ws, (past_time, past_time))

        report = cleanup_all(
            workspace_dir=ws_dir,
            upload_dir=up_dir,
            workspace_ttl=100,
            upload_ttl=100,
            dry_run=True,
        )

        assert report.dry_run is True
        assert report.workspaces_removed == 1
        assert expired_ws.exists()  # Not deleted in dry-run mode


class TestEnvironmentAndGitignore:
    """Test environment configuration templates and ignore policies."""

    def test_env_example_has_all_phase4_variables(self) -> None:
        """Verify .env.example contains all required configuration variables."""
        content = ENV_EXAMPLE.read_text(encoding="utf-8")
        required_vars = [
            "MONGODB_URI",
            "DATABASE_NAME",
            "BACKEND_PORT",
            "FRONTEND_PORT",
            "NEXT_PUBLIC_API_URL",
            "AI_API_KEY",
            "AI_MODEL",
            "UPLOAD_DIRECTORY",
            "MAX_UPLOAD_SIZE",
            "SCANNER_TIMEOUT_SECONDS",
            "GLOBAL_SCAN_TIMEOUT_SECONDS",
            "WORKSPACE_BASE_DIR",
            "WORKSPACE_TTL_SECONDS",
        ]
        for var in required_vars:
            assert var in content, f"Missing {var} in .env.example"

    def test_gitignore_ignores_credentials_and_workspaces(self) -> None:
        """Verify .gitignore blocks .env, workspaces, and uploads from source control."""
        content = GITIGNORE.read_text(encoding="utf-8")
        assert ".env" in content
        assert "workspaces/" in content
        assert "uploads/" in content


class TestScannerWorkerRunner:
    """Test scanner worker runner and tool initialization."""

    def test_get_available_scanners_initialization(self) -> None:
        """Verify get_available_scanners instantiates all scanners with timeout_seconds without binaries installed."""
        from app.scanners.bandit_scanner import BanditScanner
        from app.scanners.custom_rules.scanner import CustomRulesScanner
        from app.scanners.dependency_scanner import DependencyScanner
        from app.scanners.secrets_scanner import SecretsScanner
        from app.scanners.semgrep_scanner import SemgrepScanner
        from app.scanners.worker_runner import get_available_scanners

        scanners = get_available_scanners(timeout=45)

        # All five scanner keys present
        assert "semgrep" in scanners
        assert "bandit" in scanners
        assert "secrets" in scanners
        assert "dependency" in scanners
        assert "custom_rules" in scanners

        # Types match the expected scanner adapters
        assert isinstance(scanners["semgrep"], SemgrepScanner)
        assert isinstance(scanners["bandit"], BanditScanner)
        assert isinstance(scanners["secrets"], SecretsScanner)
        assert isinstance(scanners["dependency"], DependencyScanner)
        assert isinstance(scanners["custom_rules"], CustomRulesScanner)

        # Configured timeouts are correctly propagated
        assert scanners["semgrep"].timeout_seconds == 45.0
        assert scanners["bandit"].timeout_seconds == 45.0
        assert scanners["secrets"].timeout_seconds == 45.0
        assert scanners["dependency"].timeout_seconds == 45.0
        assert scanners["custom_rules"].timeout == 45

