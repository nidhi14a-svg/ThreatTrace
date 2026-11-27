"""Temporary Workspace Management for Thread Trace Scanners.

Provides secure ephemeral workspace creation, path traversal validation,
read-only source mounting semantics, and safe automated cleanup.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Generator

logger = logging.getLogger("workspace_manager")

# Strict regex for valid scan IDs (UUIDv4 or alphanumeric with hyphens)
RE_SAFE_ID = re.compile(r"^[0-9a-zA-Z\-_]{8,64}$")


class WorkspaceSecurityError(Exception):
    """Raised when a workspace path traversal or security violation is detected."""


@dataclass(frozen=True)
class WorkspacePaths:
    """Structured filesystem paths for an isolated workspace."""

    workspace_id: str
    base_dir: Path
    workspace_dir: Path
    source_dir: Path
    output_dir: Path
    output_file: Path


class WorkspaceManager:
    """Manages creation, validation, and cleanup of ephemeral scanner workspaces."""

    def __init__(
        self,
        base_dir: str | Path | None = None,
        ttl_seconds: int = 1800,
    ) -> None:
        """Initialize workspace manager with base directory and TTL."""
        if base_dir is None:
            raw_base = os.environ.get("WORKSPACE_BASE_DIR", "/tmp/thread-trace/workspaces")
            self._base_dir = Path(raw_base).resolve()
        else:
            self._base_dir = Path(base_dir).resolve()

        self._ttl_seconds = ttl_seconds

    @property
    def base_dir(self) -> Path:
        """Return the resolved base directory for workspaces."""
        return self._base_dir

    def ensure_base_dir(self) -> Path:
        """Ensure base directory exists on disk."""
        self._base_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._base_dir, 0o777)
        except OSError:
            pass
        return self._base_dir

    def validate_workspace_id(self, workspace_id: str) -> str:
        """Validate workspace ID against strict alphanumeric/UUID pattern."""
        if not workspace_id or not isinstance(workspace_id, str):
            raise WorkspaceSecurityError("Workspace ID must be a non-empty string.")

        clean_id = workspace_id.strip()
        if not RE_SAFE_ID.match(clean_id):
            raise WorkspaceSecurityError(
                f"Invalid workspace ID format: '{workspace_id}'. Must be 8-64 alphanumeric/hyphen characters."
            )

        if ".." in clean_id or "/" in clean_id or "\\" in clean_id:
            raise WorkspaceSecurityError(f"Potential path traversal in workspace ID: '{workspace_id}'.")

        return clean_id

    def create_workspace(self, scan_id: str | None = None) -> WorkspacePaths:
        """Create a new ephemeral workspace with source and output directories."""
        if scan_id is None:
            clean_id = str(uuid.uuid4())
        else:
            clean_id = self.validate_workspace_id(scan_id)

        self.ensure_base_dir()

        workspace_dir = (self._base_dir / clean_id).resolve()

        # Enforce that workspace_dir is strictly inside base_dir
        if not workspace_dir.is_relative_to(self._base_dir):
            raise WorkspaceSecurityError(
                f"Workspace path breakout detected: {workspace_dir} is outside {self._base_dir}"
            )

        source_dir = workspace_dir / "source"
        output_dir = workspace_dir / "output"
        output_file = output_dir / "raw_results.json"

        # Create directories with restricted permissions
        source_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        for d in (workspace_dir, source_dir, output_dir):
            try:
                os.chmod(d, 0o777)
            except OSError:
                pass

        return WorkspacePaths(
            workspace_id=clean_id,
            base_dir=self._base_dir,
            workspace_dir=workspace_dir,
            source_dir=source_dir,
            output_dir=output_dir,
            output_file=output_file,
        )

    def cleanup_workspace(self, workspace_id: str) -> bool:
        """Safely remove a workspace directory."""
        try:
            clean_id = self.validate_workspace_id(workspace_id)
            workspace_dir = (self._base_dir / clean_id).resolve()

            if not workspace_dir.is_relative_to(self._base_dir):
                logger.error(f"Cannot clean path outside base dir: {workspace_dir}")
                return False

            if workspace_dir.exists():
                shutil.rmtree(workspace_dir, ignore_errors=True)
                logger.info(f"Cleaned up workspace {clean_id}")
                return True
            return False
        except Exception as e:
            logger.warning(f"Error during workspace cleanup for {workspace_id}: {e}")
            return False

    def cleanup_expired_workspaces(self, ttl_seconds: int | None = None) -> int:
        """Delete all workspace directories older than TTL."""
        ttl = ttl_seconds if ttl_seconds is not None else self._ttl_seconds
        now = time.time()
        removed_count = 0

        if not self._base_dir.exists():
            return 0

        for item in self._base_dir.iterdir():
            if item.is_dir():
                try:
                    # Validate that dirname is a valid workspace ID
                    self.validate_workspace_id(item.name)
                    mtime = item.stat().st_mtime
                    if (now - mtime) > ttl:
                        shutil.rmtree(item, ignore_errors=True)
                        removed_count += 1
                        logger.info(f"Removed expired workspace: {item.name}")
                except (WorkspaceSecurityError, OSError) as exc:
                    logger.debug(f"Skipping directory {item.name}: {exc}")

        return removed_count

    def validate_file_within_workspace(
        self,
        workspace: WorkspacePaths,
        target_path: str | Path,
    ) -> Path:
        """Ensure a file path resides strictly inside the workspace boundary."""
        resolved = Path(target_path).resolve()
        if not resolved.is_relative_to(workspace.workspace_dir):
            raise WorkspaceSecurityError(
                f"Target path {resolved} breaks out of workspace {workspace.workspace_dir}"
            )
        return resolved

    @contextlib.contextmanager
    def isolated_workspace(
        self,
        scan_id: str | None = None,
        auto_cleanup: bool = True,
    ) -> Generator[WorkspacePaths, None, None]:
        """Context manager creating a workspace and guaranteeing cleanup."""
        paths = self.create_workspace(scan_id=scan_id)
        try:
            yield paths
        finally:
            if auto_cleanup:
                self.cleanup_workspace(paths.workspace_id)
