#!/usr/bin/env python3
"""Cleanup and retention management script for Thread Trace.

Sweeps expired workspaces and temporary upload archives to prevent disk exhaustion,
enforcing path traversal defenses and strict retention time-to-live (TTL) limits.
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cleanup_workspaces")


@dataclass
class CleanupReport:
    """Summary report of cleanup operations."""

    workspaces_scanned: int = 0
    workspaces_removed: int = 0
    uploads_scanned: int = 0
    uploads_removed: int = 0
    bytes_freed: int = 0
    dry_run: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspaces_scanned": self.workspaces_scanned,
            "workspaces_removed": self.workspaces_removed,
            "uploads_scanned": self.uploads_scanned,
            "uploads_removed": self.uploads_removed,
            "bytes_freed": self.bytes_freed,
            "dry_run": self.dry_run,
            "errors": self.errors,
        }


def get_dir_size(path: Path) -> int:
    """Calculate total byte size of a directory recursively."""
    total = 0
    try:
        if path.is_file():
            return path.stat().st_size
        for entry in path.rglob("*"):
            if entry.is_file() and not entry.is_symlink():
                try:
                    total += entry.stat().st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


def is_safe_child(child: Path, parent: Path) -> bool:
    """Verify child path is strictly a descendant of parent path."""
    try:
        resolved_child = child.resolve()
        resolved_parent = parent.resolve()
        return resolved_child.is_relative_to(resolved_parent) and resolved_child != resolved_parent
    except Exception:
        return False


def clean_workspaces(
    workspace_dir: Path,
    ttl_seconds: int = 1800,
    dry_run: bool = False,
    report: CleanupReport | None = None,
) -> CleanupReport:
    """Sweep and remove workspace directories older than ttl_seconds."""
    if report is None:
        report = CleanupReport(dry_run=dry_run)

    if not workspace_dir.exists():
        logger.debug(f"Workspace directory does not exist: {workspace_dir}")
        return report

    now = time.time()
    try:
        entries = list(workspace_dir.iterdir())
    except OSError as err:
        msg = f"Failed to list workspace directory {workspace_dir}: {err}"
        logger.error(msg)
        report.errors.append(msg)
        return report

    for entry in entries:
        if not entry.is_dir() or entry.is_symlink():
            continue

        report.workspaces_scanned += 1

        if not is_safe_child(entry, workspace_dir):
            msg = f"Path safety violation detected: {entry} is not a valid child of {workspace_dir}"
            logger.warning(msg)
            report.errors.append(msg)
            continue

        try:
            mtime = entry.stat().st_mtime
            age_seconds = now - mtime
            if age_seconds > ttl_seconds:
                size = get_dir_size(entry)
                if dry_run:
                    logger.info(f"[DRY-RUN] Would remove expired workspace: {entry.name} (age: {int(age_seconds)}s, size: {size} bytes)")
                    report.workspaces_removed += 1
                    report.bytes_freed += size
                else:
                    shutil.rmtree(entry, ignore_errors=True)
                    logger.info(f"Removed expired workspace: {entry.name} (age: {int(age_seconds)}s, freed: {size} bytes)")
                    report.workspaces_removed += 1
                    report.bytes_freed += size
        except Exception as err:
            msg = f"Error processing workspace {entry}: {err}"
            logger.error(msg)
            report.errors.append(msg)

    return report


def clean_uploads(
    upload_dir: Path,
    ttl_seconds: int = 900,
    dry_run: bool = False,
    report: CleanupReport | None = None,
) -> CleanupReport:
    """Sweep and remove temporary upload archives older than ttl_seconds."""
    if report is None:
        report = CleanupReport(dry_run=dry_run)

    if not upload_dir.exists():
        logger.debug(f"Upload directory does not exist: {upload_dir}")
        return report

    now = time.time()
    try:
        entries = list(upload_dir.iterdir())
    except OSError as err:
        msg = f"Failed to list upload directory {upload_dir}: {err}"
        logger.error(msg)
        report.errors.append(msg)
        return report

    for entry in entries:
        if not entry.is_file() or entry.is_symlink():
            continue

        report.uploads_scanned += 1

        if not is_safe_child(entry, upload_dir):
            msg = f"Path safety violation detected: {entry} is not a valid child of {upload_dir}"
            logger.warning(msg)
            report.errors.append(msg)
            continue

        try:
            mtime = entry.stat().st_mtime
            age_seconds = now - mtime
            if age_seconds > ttl_seconds:
                size = entry.stat().st_size
                if dry_run:
                    logger.info(f"[DRY-RUN] Would remove expired upload: {entry.name} (age: {int(age_seconds)}s, size: {size} bytes)")
                    report.uploads_removed += 1
                    report.bytes_freed += size
                else:
                    entry.unlink(missing_ok=True)
                    logger.info(f"Removed expired upload: {entry.name} (age: {int(age_seconds)}s, freed: {size} bytes)")
                    report.uploads_removed += 1
                    report.bytes_freed += size
        except Exception as err:
            msg = f"Error processing upload {entry}: {err}"
            logger.error(msg)
            report.errors.append(msg)

    return report


def cleanup_all(
    workspace_dir: str | Path | None = None,
    upload_dir: str | Path | None = None,
    workspace_ttl: int = 1800,
    upload_ttl: int = 900,
    dry_run: bool = False,
) -> CleanupReport:
    """Execute complete cleanup sweep across both workspaces and uploads."""
    ws_dir = (
        Path(workspace_dir)
        if workspace_dir
        else Path(os.environ.get("WORKSPACE_BASE_DIR", "/tmp/thread-trace/workspaces"))
    )
    up_dir = (
        Path(upload_dir)
        if upload_dir
        else Path(os.environ.get("UPLOAD_DIRECTORY", "/tmp/thread-trace/uploads"))
    )

    report = CleanupReport(dry_run=dry_run)
    clean_workspaces(ws_dir, ttl_seconds=workspace_ttl, dry_run=dry_run, report=report)
    clean_uploads(up_dir, ttl_seconds=upload_ttl, dry_run=dry_run, report=report)
    return report


def main() -> int:
    """CLI entrypoint for cleanup script."""
    parser = argparse.ArgumentParser(
        prog="cleanup_workspaces",
        description="Sweep expired Thread Trace workspaces and upload archives.",
    )
    parser.add_argument(
        "--workspace-dir",
        type=str,
        default=os.environ.get("WORKSPACE_BASE_DIR", "/tmp/thread-trace/workspaces"),
        help="Path to temporary workspaces directory (default: /tmp/thread-trace/workspaces)",
    )
    parser.add_argument(
        "--upload-dir",
        type=str,
        default=os.environ.get("UPLOAD_DIRECTORY", "/tmp/thread-trace/uploads"),
        help="Path to temporary uploads directory (default: /tmp/thread-trace/uploads)",
    )
    parser.add_argument(
        "--ttl-seconds",
        type=int,
        default=int(os.environ.get("WORKSPACE_TTL_SECONDS", "1800")),
        help="TTL in seconds for workspaces (default: 1800s / 30m)",
    )
    parser.add_argument(
        "--upload-ttl-seconds",
        type=int,
        default=900,
        help="TTL in seconds for uploads (default: 900s / 15m)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview files that would be removed without deleting them",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational output",
    )

    args = parser.parse_args()

    if args.quiet:
        logger.setLevel(logging.WARNING)

    report = cleanup_all(
        workspace_dir=args.workspace_dir,
        upload_dir=args.upload_dir,
        workspace_ttl=args.ttl_seconds,
        upload_ttl=args.upload_ttl_seconds,
        dry_run=args.dry_run,
    )

    prefix = "[DRY-RUN] " if report.dry_run else ""
    logger.info(
        f"{prefix}Cleanup complete: {report.workspaces_removed}/{report.workspaces_scanned} workspaces removed, "
        f"{report.uploads_removed}/{report.uploads_scanned} uploads removed, "
        f"{report.bytes_freed} bytes freed, {len(report.errors)} errors."
    )

    return 0 if not report.errors else 1


if __name__ == "__main__":
    sys.exit(main())
