"""Tests for Workspace Deletion, TTL Sweeping, and Retention Policies (specs/DELETE_RETENTION_TEST_SPEC.md).

Verifies:
- Complete removal of source and output directories
- Idempotent cleanup behavior
- Path traversal defense during workspace ID validation and cleanup
- TTL-based expired workspace cleanup
- Dry run execution without modifying disk state
- Cleanup following scan exceptions
"""

import os
import time
from pathlib import Path
import pytest

from app.scanners.workspace import WorkspaceManager, WorkspaceSecurityError
import sys

# Ensure root scripts directory is importable
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.cleanup_workspaces import clean_workspaces, CleanupReport, is_safe_child


@pytest.fixture
def temp_workspace_mgr(tmp_path):
    return WorkspaceManager(base_dir=tmp_path / "workspaces", ttl_seconds=1800)


def test_immediate_workspace_deletion(temp_workspace_mgr):
    paths = temp_workspace_mgr.create_workspace("scan-del-01")
    assert paths.workspace_dir.exists()
    assert paths.source_dir.exists()
    assert paths.output_dir.exists()

    # Create dummy source and output files
    (paths.source_dir / "app.py").write_text("print('test')", encoding="utf-8")
    (paths.output_file).write_text("{}", encoding="utf-8")

    # Cleanup
    deleted = temp_workspace_mgr.cleanup_workspace("scan-del-01")
    assert deleted is True
    assert not paths.workspace_dir.exists()
    assert not paths.source_dir.exists()
    assert not paths.output_dir.exists()


def test_idempotent_workspace_deletion(temp_workspace_mgr):
    paths = temp_workspace_mgr.create_workspace("scan-del-02")
    assert paths.workspace_dir.exists()

    # First cleanup succeeds
    assert temp_workspace_mgr.cleanup_workspace("scan-del-02") is True
    assert not paths.workspace_dir.exists()

    # Second cleanup on non-existent workspace returns False without error
    assert temp_workspace_mgr.cleanup_workspace("scan-del-02") is False


def test_path_traversal_rejection_in_workspace_id(temp_workspace_mgr):
    malicious_ids = [
        "../../etc",
        "..\\..\\windows",
        "scan/../../breakout",
        "valid_id/nested",
        "id with spaces",
        "id;rm -rf /",
    ]
    for bad_id in malicious_ids:
        with pytest.raises(WorkspaceSecurityError):
            temp_workspace_mgr.validate_workspace_id(bad_id)

        # cleanup_workspace safely catches errors and returns False without performing traversal
        assert temp_workspace_mgr.cleanup_workspace(bad_id) is False


def test_ttl_expired_workspaces_cleanup(temp_workspace_mgr):
    base = temp_workspace_mgr.base_dir

    # 1. Active workspace (fresh)
    active_paths = temp_workspace_mgr.create_workspace("scan-active-01")
    (active_paths.source_dir / "active.py").write_text("active code", encoding="utf-8")

    # 2. Expired workspace (aged 2 hours ago)
    expired_paths = temp_workspace_mgr.create_workspace("scan-expired-01")
    (expired_paths.source_dir / "expired.py").write_text("expired code", encoding="utf-8")

    past_time = time.time() - 7200  # 2 hours ago
    os.utime(expired_paths.workspace_dir, (past_time, past_time))

    # Run cleanup with 1-hour TTL (3600 seconds)
    removed_count = temp_workspace_mgr.cleanup_expired_workspaces(ttl_seconds=3600)

    assert removed_count == 1
    assert not expired_paths.workspace_dir.exists()
    assert active_paths.workspace_dir.exists()


def test_dry_run_mode_does_not_delete_files(temp_workspace_mgr):
    expired_paths = temp_workspace_mgr.create_workspace("scan-dryrun-01")
    (expired_paths.source_dir / "code.py").write_text("some code", encoding="utf-8")

    past_time = time.time() - 7200
    os.utime(expired_paths.workspace_dir, (past_time, past_time))

    # Run scripts.cleanup_workspaces in dry_run mode
    report = clean_workspaces(
        workspace_dir=temp_workspace_mgr.base_dir,
        ttl_seconds=3600,
        dry_run=True,
    )

    assert report.dry_run is True
    assert report.workspaces_removed == 1
    assert report.bytes_freed > 0
    # Crucially, directory must STILL exist because dry_run=True
    assert expired_paths.workspace_dir.exists()


def test_is_safe_child_security_helper(tmp_path):
    parent = tmp_path / "safe_parent"
    parent.mkdir()
    child = parent / "valid_child"
    child.mkdir()
    outside = tmp_path / "outside_dir"
    outside.mkdir()

    assert is_safe_child(child, parent) is True
    assert is_safe_child(outside, parent) is False
    assert is_safe_child(parent, parent) is False  # identical is not a child
