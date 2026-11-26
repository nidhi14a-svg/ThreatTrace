import asyncio
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult


class BanditScanner(BaseScanner):
    """
    Bandit static analysis scanner adapter for Python source code.

    Executes the Bandit CLI in an isolated subprocess, captures and validates
    JSON findings, enforces resource bounds, checks for Python source files,
    normalizes finding filepaths to relative workspace coordinates, and maps
    Bandit exit code semantics (exit code 1 on findings) to the shared
    ScannerExecutionResult contract.
    """

    name: str = "bandit"

    def __init__(
        self,
        binary_path: str = "bandit",
        timeout_seconds: float = 60.0,
        max_output_bytes: int = 10 * 1024 * 1024,
        excluded_paths: str = ".venv,venv,env,node_modules,tests,__pycache__,.pytest_cache",
        config_path: str | None = None,
        allow_skip_if_missing: bool = False,
    ) -> None:
        """
        Initialize the BanditScanner with configurable security limits.

        Args:
            binary_path: Path or command name for the Bandit executable.
            timeout_seconds: Hard execution timeout for the scan subprocess.
            max_output_bytes: Maximum allowed stdout/stderr buffer size in bytes (10MB default).
            excluded_paths: Comma-separated list of directories to exclude from scanning.
            config_path: Optional path to a custom Bandit YAML configuration file.
            allow_skip_if_missing: If True, mark missing binary as 'skipped' instead of 'failed'.
        """
        self.binary_path = os.environ.get("BANDIT_BINARY_PATH", binary_path)
        self.timeout_seconds = float(
            os.environ.get("BANDIT_TIMEOUT_SECONDS", str(timeout_seconds))
        )
        self.max_output_bytes = int(
            os.environ.get("BANDIT_MAX_OUTPUT_BYTES", str(max_output_bytes))
        )
        self.excluded_paths = os.environ.get("BANDIT_EXCLUDED_PATHS", excluded_paths)
        self.config_path = os.environ.get("BANDIT_CONFIG_PATH", config_path)
        self.allow_skip_if_missing = allow_skip_if_missing

    def is_available(self) -> bool:
        """Check if the Bandit executable is available on PATH."""
        return shutil.which(self.binary_path) is not None

    async def scan(self, workspace: str) -> ScannerExecutionResult:
        """
        Execute Bandit against an isolated workspace directory.

        Args:
            workspace: Absolute path to the isolated directory containing extracted target code.

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

        # 2. Check for Python Source Files in Workspace
        if not self._has_python_files(workspace_path):
            return self.create_result(
                status="skipped",
                findings=[],
                duration_seconds=round(time.monotonic() - start_time, 4),
                error=None,
            )

        # 3. Check binary availability if configured to skip
        if self.allow_skip_if_missing and not self.is_available():
            return self.create_result(
                status="skipped",
                findings=[],
                duration_seconds=round(time.monotonic() - start_time, 4),
                error=f"Bandit executable not found: '{self.binary_path}'",
            )

        # 4. Construct Command (list of arguments, never shell=True)
        cmd = [
            self.binary_path,
            "-r",
            str(workspace_path),
            "-f",
            "json",
            "-q",
        ]

        if self.excluded_paths and self.excluded_paths.strip():
            cmd.extend(["-x", self.excluded_paths.strip()])

        if self.config_path and self.config_path.strip():
            cmd.extend(["-c", self.config_path.strip()])

        # 5. Execute Subprocess Safely
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(workspace_path),
            )
        except FileNotFoundError:
            return self.create_result(
                status="skipped" if self.allow_skip_if_missing else "failed",
                findings=[],
                duration_seconds=round(time.monotonic() - start_time, 4),
                error=f"Bandit executable not found: '{self.binary_path}'",
            )
        except (PermissionError, OSError) as exc:
            return self.create_result(
                status="failed",
                findings=[],
                duration_seconds=round(time.monotonic() - start_time, 4),
                error=f"Failed to execute Bandit process: {self._sanitize_error(str(exc))}",
            )

        # 6. Capture stdout/stderr with Timeout and Memory Bounds
        try:
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            try:
                process.kill()
                await process.wait()
            except (ProcessLookupError, OSError):
                pass
            return self.create_result(
                status="failed",
                findings=[],
                duration_seconds=round(time.monotonic() - start_time, 4),
                error=f"Bandit execution timed out after {self.timeout_seconds} seconds",
            )

        duration_seconds = round(time.monotonic() - start_time, 4)

        # 7. Bounded Output Handling
        if len(stdout_data) > self.max_output_bytes:
            return self.create_result(
                status="failed",
                findings=[],
                duration_seconds=duration_seconds,
                error=(
                    f"Bandit stdout exceeded maximum output limit of "
                    f"{self.max_output_bytes} bytes (received {len(stdout_data)} bytes)"
                ),
            )

        stdout_text = stdout_data.decode("utf-8", errors="replace")
        stderr_text = stderr_data.decode("utf-8", errors="replace")
        safe_stderr = self._sanitize_error(stderr_text)

        # 8. Parse JSON Output
        try:
            data = json.loads(stdout_text)
        except json.JSONDecodeError:
            error_msg = (
                f"Malformed Bandit JSON output (exit code {process.returncode}): {safe_stderr}"
                if safe_stderr
                else f"Malformed Bandit JSON output: failed to decode stdout (exit code {process.returncode})"
            )
            return self.create_result(
                status="failed",
                findings=[],
                duration_seconds=duration_seconds,
                error=error_msg,
            )

        if not isinstance(data, dict):
            return self.create_result(
                status="failed",
                findings=[],
                duration_seconds=duration_seconds,
                error="Malformed Bandit output: expected root JSON object",
            )

        # 9. Extract and Sanitize Findings
        raw_results = data.get("results")
        if not isinstance(raw_results, list):
            raw_results = []

        raw_errors = data.get("errors")
        if not isinstance(raw_errors, list):
            raw_errors = []

        findings: list[dict[str, Any]] = []
        for item in raw_results:
            if isinstance(item, dict):
                parsed = self._parse_finding(item, workspace_path)
                if parsed is not None:
                    findings.append(parsed)

        # 10. Determine Execution Status
        # Note: Bandit exits with code 0 on no findings, and exit code 1 when findings are present.
        if process.returncode in (0, 1):
            if raw_errors:
                status = "partial"
                error = f"Bandit completed with syntax/parse warnings on {len(raw_errors)} file(s)"
            else:
                status = "success"
                error = None
        else:
            # Returncode >= 2 indicates an execution error
            if findings:
                status = "partial"
                error = safe_stderr or f"Bandit completed with findings and exit code {process.returncode}"
            else:
                status = "failed"
                error = safe_stderr or f"Bandit process exited with error code {process.returncode}"

        return self.create_result(
            status=status,
            findings=findings,
            duration_seconds=duration_seconds,
            error=error,
        )

    def _parse_finding(
        self,
        item: dict[str, Any],
        workspace_root: Path,
    ) -> dict[str, Any] | None:
        """
        Parse an individual Bandit raw result dictionary into a consistent raw finding.

        Preserves tool-native attributes without instantiating the normalized Finding schema.
        """
        test_id = str(item.get("test_id") or "")
        rule_id = f"bandit.{test_id}" if test_id else "bandit.unknown"
        test_name = item.get("test_name")
        raw_category = str(test_name) if test_name else None

        raw_filename = str(item.get("filename") or "")
        relative_path = self._sanitize_path(raw_filename, workspace_root)

        severity = str(item.get("issue_severity") or "MEDIUM").upper()
        confidence = str(item.get("issue_confidence") or "MEDIUM").upper()

        line_number = item.get("line_number")
        if not isinstance(line_number, int):
            line_number = None

        line_range = item.get("line_range")
        if not isinstance(line_range, list):
            line_range = [line_number] if line_number is not None else []

        issue_text = str(item.get("issue_text") or "")
        raw_code = str(item.get("code") or "")

        # Bound evidence snippet to at most 1000 characters
        evidence = raw_code[:1000] if raw_code else ""

        # Construct raw metadata dictionary preserving native attributes
        metadata: dict[str, Any] = {
            "test_id": test_id,
            "test_name": test_name,
            "cwe": item.get("issue_cwe"),
            "confidence": confidence,
            "more_info": item.get("more_info"),
        }

        return {
            "scanner_name": self.name,
            "rule_id": rule_id,
            "severity": severity,
            "confidence": confidence,
            "raw_category": raw_category,
            "file": relative_path,
            "line": line_number,
            "line_range": line_range,
            "message": issue_text,
            "evidence": evidence,
            "metadata": metadata,
        }

    def _has_python_files(self, workspace_root: Path) -> bool:
        """
        Check if the workspace contains any Python source files (.py),
        ignoring standard excluded directories.
        """
        excluded_set = {
            item.strip().lower()
            for item in self.excluded_paths.split(",")
            if item.strip()
        }

        try:
            for root, dirs, files in os.walk(workspace_root):
                # Filter out excluded subdirectories in-place
                dirs[:] = [d for d in dirs if d.lower() not in excluded_set]
                for file in files:
                    if file.lower().endswith(".py"):
                        return True
        except (PermissionError, OSError):
            return False

        return False

    def _sanitize_path(self, raw_path: str, workspace_root: Path) -> str:
        """
        Sanitize and resolve a raw finding path to ensure it remains strictly
        within the scanned workspace.

        Returns POSIX-formatted relative path, or a safe rejection marker if
        the path escapes the workspace root.
        """
        if not raw_path or not raw_path.strip():
            return ""

        try:
            path_obj = Path(raw_path.strip())
            if path_obj.is_absolute():
                resolved_target = path_obj.resolve()
            else:
                resolved_target = (workspace_root / path_obj).resolve()

            # Verify that the target path is strictly within workspace_root
            relative_target = resolved_target.relative_to(workspace_root)
            return relative_target.as_posix()
        except (ValueError, RuntimeError):
            # Path escapes the workspace root (directory traversal attempt)
            return "[REJECTED_OUTSIDE_WORKSPACE]"

    def _sanitize_error(self, raw_stderr: str, max_length: int = 500) -> str | None:
        """
        Strip ANSI codes and summarize stderr safely without exposing secrets
        or repository dumps.
        """
        if not raw_stderr or not raw_stderr.strip():
            return None

        cleaned = raw_stderr.strip()
        # Strip ANSI escape sequences
        cleaned = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", cleaned)

        # Collect first few non-empty lines for a safe diagnostic summary
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        summary = " | ".join(lines[:3]) if lines else cleaned

        if len(summary) > max_length:
            summary = summary[:max_length] + "..."

        return summary
