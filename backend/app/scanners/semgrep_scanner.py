import asyncio
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult


class SemgrepScanner(BaseScanner):
    """
    Semgrep static analysis scanner adapter for Thread Trace.

    Executes the Semgrep CLI in an isolated subprocess, captures and validates
    JSON findings, enforces resource bounds, normalizes finding filepaths to
    relative workspace coordinates, and maps execution states to the shared
    ScannerExecutionResult contract.
    """

    name: str = "semgrep"

    def __init__(
        self,
        binary_path: str = "semgrep",
        rules: str = "p/owasp-top-ten",
        timeout_seconds: float = 60.0,
        max_output_bytes: int = 10 * 1024 * 1024,
        max_target_bytes: int = 1000000,
        allow_skip_if_missing: bool = False,
    ) -> None:
        """
        Initialize the SemgrepScanner with configurable security limits.

        Args:
            binary_path: Path or command name for the Semgrep executable.
            rules: Semgrep rule pack or config path (defaults to 'p/owasp-top-ten').
            timeout_seconds: Hard execution timeout for the scan subprocess.
            max_output_bytes: Maximum allowed stdout/stderr buffer size in bytes (10MB default).
            max_target_bytes: Semgrep per-file evaluation ceiling (1MB default).
            allow_skip_if_missing: If True, mark missing binary as 'skipped' instead of 'failed'.
        """
        self.binary_path = os.environ.get("SEMGREP_BINARY_PATH", binary_path)
        default_rules = "/app/rules/owasp-top-ten.yml" if Path("/app/rules/owasp-top-ten.yml").exists() else "p/owasp-top-ten"
        env_rules = os.environ.get("SEMGREP_RULES")
        if env_rules:
            self.rules = env_rules
        elif rules != "p/owasp-top-ten":
            self.rules = rules
        else:
            self.rules = default_rules

        self.timeout_seconds = float(
            os.environ.get("SEMGREP_TIMEOUT_SECONDS", str(timeout_seconds))
        )
        self.max_output_bytes = int(
            os.environ.get("SEMGREP_MAX_OUTPUT_BYTES", str(max_output_bytes))
        )
        self.max_target_bytes = int(
            os.environ.get("SEMGREP_MAX_TARGET_BYTES", str(max_target_bytes))
        )
        self.allow_skip_if_missing = allow_skip_if_missing

    def is_available(self) -> bool:
        """Check if the Semgrep executable is available on PATH."""
        return shutil.which(self.binary_path) is not None

    async def scan(self, workspace: str) -> ScannerExecutionResult:
        """
        Execute Semgrep against an isolated workspace directory.

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

        # 2. Check for empty workspace
        try:
            has_files = any(workspace_path.iterdir())
        except (PermissionError, OSError) as exc:
            return self.create_result(
                status="failed",
                duration_seconds=round(time.monotonic() - start_time, 4),
                error=f"Cannot access workspace directory: {self._sanitize_error(str(exc))}",
            )

        if not has_files:
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
                error=f"Semgrep executable not found: '{self.binary_path}'",
            )

        # 4. Construct Command (list of arguments, never shell=True)
        cmd = [
            self.binary_path,
            "scan",
            "--json",
            "--config",
            self.rules,
            "--metrics=off",
            "--disable-version-check",
            "--max-target-bytes",
            str(self.max_target_bytes),
            "--timeout",
            "10",
            str(workspace_path),
        ]

        # 5. Execute Subprocess Safely
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(workspace_path),
                env={**os.environ, "PYTHONWARNINGS": "ignore"},
            )
        except FileNotFoundError:
            return self.create_result(
                status="skipped" if self.allow_skip_if_missing else "failed",
                findings=[],
                duration_seconds=round(time.monotonic() - start_time, 4),
                error=f"Semgrep executable not found: '{self.binary_path}'",
            )
        except (PermissionError, OSError) as exc:
            return self.create_result(
                status="failed",
                findings=[],
                duration_seconds=round(time.monotonic() - start_time, 4),
                error=f"Failed to execute Semgrep process: {self._sanitize_error(str(exc))}",
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
                error=f"Semgrep execution timed out after {self.timeout_seconds} seconds",
            )

        duration_seconds = round(time.monotonic() - start_time, 4)

        # 7. Bounded Output Handling
        if len(stdout_data) > self.max_output_bytes:
            return self.create_result(
                status="failed",
                findings=[],
                duration_seconds=duration_seconds,
                error=(
                    f"Semgrep stdout exceeded maximum output limit of "
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
                f"Malformed Semgrep JSON output (exit code {process.returncode}): {safe_stderr}"
                if safe_stderr
                else f"Malformed Semgrep JSON output: failed to decode stdout (exit code {process.returncode})"
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
                error="Malformed Semgrep output: expected root JSON object",
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
        if process.returncode == 0:
            if raw_errors:
                status = "partial"
                error = f"Semgrep completed with warnings/errors on {len(raw_errors)} file(s)"
            else:
                status = "success"
                error = None
        else:
            # Semgrep may exit non-zero if errors occurred or findings were reported
            if findings:
                status = "partial"
                error = safe_stderr or f"Semgrep completed with findings and exit code {process.returncode}"
            else:
                status = "failed"
                error = safe_stderr or f"Semgrep process exited with non-zero code {process.returncode}"

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
        Parse an individual Semgrep raw result dictionary into a consistent raw finding.

        Preserves tool-native attributes without instantiating the normalized Finding schema.
        """
        check_id = str(item.get("check_id") or "semgrep.unknown-rule")
        raw_path = str(item.get("path") or "")

        # Path sanitization: ensure path is strictly relative to workspace
        relative_path = self._sanitize_path(raw_path, workspace_root)

        # Line and column parsing (when available)
        start_dict = item.get("start")
        end_dict = item.get("end")

        start_line = start_dict.get("line") if isinstance(start_dict, dict) else None
        start_col = start_dict.get("col") if isinstance(start_dict, dict) else None
        end_line = end_dict.get("line") if isinstance(end_dict, dict) else None
        end_col = end_dict.get("col") if isinstance(end_dict, dict) else None

        extra = item.get("extra")
        if not isinstance(extra, dict):
            extra = {}

        severity = str(extra.get("severity") or "WARNING")
        message = str(extra.get("message") or "")
        raw_lines = str(extra.get("lines") or "")

        # Bound evidence snippet to at most 1000 characters
        evidence = raw_lines[:1000] if raw_lines else ""

        metadata = extra.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}

        # Preserve original category / subcategory when available
        raw_category = metadata.get("category") or metadata.get("subcategory")
        if raw_category is not None:
            raw_category = str(raw_category)

        return {
            "scanner_name": self.name,
            "rule_id": check_id,
            "severity": severity,
            "raw_category": raw_category,
            "file": relative_path,
            "line": start_line,
            "col": start_col,
            "end_line": end_line,
            "end_col": end_col,
            "message": message,
            "evidence": evidence,
            "metadata": metadata,
        }

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

        # Collect last few non-empty lines so warnings at the top don't hide the actual error
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        summary = " | ".join(lines[-5:]) if lines else cleaned

        if len(summary) > max_length:
            summary = summary[:max_length] + "..."

        return summary