"""
Custom rules scanner adapter for Thread Trace.

Integrates custom security detection rules into the BaseScanner contract.
Scans workspace source code against registered custom rules, captures findings,
enforces evidence sanitization, and produces standard ScannerExecutionResult.
"""

import os
import time
from pathlib import Path
from typing import Any

from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult
from app.scanners.custom_rules.registry import RuleRegistry, default_registry


class CustomRulesScanner(BaseScanner):
    """
    Adapter bridging custom security detection rules with the BaseScanner contract.

    Evaluates project-specific security rules across supported files in an isolated
    workspace directory without requiring third-party CLI binaries.
    """

    name: str = "custom-rules"

    IGNORED_DIRS: set[str] = {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".eggs",
        "dist",
        "build",
        ".next",
    }

    MAX_FILE_BYTES: int = 2 * 1024 * 1024  # 2MB file limit to prevent DoS

    def __init__(self, registry: RuleRegistry | None = None, timeout: int = 60) -> None:
        """Initialize CustomRulesScanner with a specific or default rule registry."""
        self.registry = registry or default_registry
        self.timeout = timeout

    async def scan(self, workspace: str) -> ScannerExecutionResult:
        """
        Execute registered custom security rules against an isolated workspace directory.

        Args:
            workspace: Absolute path to the isolated directory containing target source code.

        Returns:
            ScannerExecutionResult: Structured result containing raw findings, status, duration, and error.
        """
        start_time = time.monotonic()

        # 1. Workspace Validation
        if not workspace or not str(workspace).strip():
            return self.create_result(
                status="failed",
                duration_seconds=0.0,
                error="Workspace path is required and cannot be empty.",
            )

        workspace_path = Path(workspace).resolve()

        if not workspace_path.exists():
            return self.create_result(
                status="skipped",
                findings=[],
                duration_seconds=0.0,
                error=None,
            )

        if not workspace_path.is_dir():
            return self.create_result(
                status="failed",
                duration_seconds=0.0,
                error=f"Workspace path is not a directory: '{workspace}'",
            )

        # 2. Check for empty workspace
        try:
            has_files = any(workspace_path.iterdir())
        except (PermissionError, OSError) as exc:
            return self.create_result(
                status="failed",
                duration_seconds=time.monotonic() - start_time,
                error=f"Cannot access workspace directory: {exc}",
            )

        if not has_files:
            return self.create_result(
                status="skipped",
                findings=[],
                duration_seconds=time.monotonic() - start_time,
                error=None,
            )

        # 3. Traverse and evaluate files against registered rules
        all_findings: list[dict[str, Any]] = []

        try:
            for root, dirs, files in os.walk(workspace_path):
                dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRS]

                for file_name in files:
                    file_path = Path(root) / file_name
                    ext = file_path.suffix.lower()

                    # Only inspect files whose extension has at least one registered rule
                    if not self.registry.get_rules_for_extension(ext):
                        continue

                    # Check file size limit
                    try:
                        if file_path.stat().st_size > self.MAX_FILE_BYTES:
                            continue
                        content = file_path.read_text(encoding="utf-8", errors="replace")
                    except (PermissionError, OSError):
                        continue

                    rel_path = self.sanitize_path(str(file_path), workspace_path)
                    if rel_path == "[REJECTED_OUTSIDE_WORKSPACE]":
                        continue

                    file_findings = self.registry.evaluate_file(rel_path, content)
                    all_findings.extend(file_findings)

        except Exception as exc:
            return self.create_result(
                status="failed",
                duration_seconds=time.monotonic() - start_time,
                error=f"Custom rules scan encountered unexpected error: {exc}",
            )

        duration = time.monotonic() - start_time
        return self.create_result(
            status="success",
            findings=all_findings,
            duration_seconds=duration,
            error=None,
        )
