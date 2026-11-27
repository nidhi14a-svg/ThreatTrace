import asyncio
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult


class SecretsScanner(BaseScanner):
    """
    Secrets and sensitive information scanner adapter for Thread Trace.

    Integrates Gitleaks for detection of hardcoded credentials, API keys,
    tokens, and private keys. Executes in directory mode (--no-git), captures
    structured JSON findings, applies mandatory in-memory redaction on all
    evidence context, normalizes file paths to workspace coordinates, and maps
    Gitleaks exit code semantics (exit code 1 on leaks) to the shared
    ScannerExecutionResult contract.
    """

    name: str = "secrets"

    def __init__(
        self,
        binary_path: str = "gitleaks",
        timeout_seconds: float = 60.0,
        max_output_bytes: int = 10 * 1024 * 1024,
        config_path: str | None = None,
        allow_skip_if_missing: bool = False,
    ) -> None:
        """
        Initialize the SecretsScanner with configurable security parameters.

        Args:
            binary_path: Path or command name for the Gitleaks executable.
            timeout_seconds: Hard execution timeout for the scan subprocess.
            max_output_bytes: Maximum allowed stdout/stderr buffer size in bytes (10MB default).
            config_path: Optional path to a custom Gitleaks TOML configuration file.
            allow_skip_if_missing: If True, mark missing binary as 'skipped' instead of 'failed'.
        """
        self.binary_path = os.environ.get("GITLEAKS_BINARY_PATH", binary_path)
        self.timeout_seconds = float(
            os.environ.get("GITLEAKS_TIMEOUT_SECONDS", str(timeout_seconds))
        )
        self.max_output_bytes = int(
            os.environ.get("GITLEAKS_MAX_OUTPUT_BYTES", str(max_output_bytes))
        )
        self.config_path = os.environ.get("GITLEAKS_CONFIG_PATH", config_path)
        self.allow_skip_if_missing = allow_skip_if_missing

    def is_available(self) -> bool:
        """Check if the Gitleaks executable is available on PATH."""
        return shutil.which(self.binary_path) is not None

    async def scan(self, workspace: str) -> ScannerExecutionResult:
        """
        Execute Gitleaks secret detection against an isolated workspace directory.

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
                error=f"Gitleaks executable not found: '{self.binary_path}'",
            )

        # 4. Prepare Ephemeral Report File for Safe Output Capture
        report_file: Path | None = None
        try:
            tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            tmp.close()
            report_file = Path(tmp.name)
        except (OSError, IOError):
            report_file = None

        # 5. Construct Command (list of arguments, never shell=True)
        cmd = [
            self.binary_path,
            "dir",
            str(workspace_path),
            "--report-format",
            "json",
            "--redact",
        ]

        if report_file is not None:
            cmd.extend(["--report-path", str(report_file)])

        if self.config_path and self.config_path.strip():
            cmd.extend(["--config", self.config_path.strip()])

        # 6. Execute Subprocess Safely
        try:
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
                    error=f"Gitleaks executable not found: '{self.binary_path}'",
                )
            except (PermissionError, OSError) as exc:
                return self.create_result(
                    status="failed",
                    findings=[],
                    duration_seconds=round(time.monotonic() - start_time, 4),
                    error=f"Failed to execute Gitleaks process: {self._sanitize_error(str(exc))}",
                )

            # 7. Capture stdout/stderr with Timeout and Memory Bounds
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
                    error=f"Gitleaks execution timed out after {self.timeout_seconds} seconds",
                )

            duration_seconds = round(time.monotonic() - start_time, 4)

            # 8. Read Report Content (from report file or fallback to stdout)
            report_text = ""
            if report_file is not None and report_file.exists() and report_file.stat().st_size > 0:
                try:
                    report_text = report_file.read_text(encoding="utf-8", errors="replace")
                except (OSError, IOError):
                    report_text = stdout_data.decode("utf-8", errors="replace")
            else:
                report_text = stdout_data.decode("utf-8", errors="replace")

            # Check bounded size
            if len(report_text) > self.max_output_bytes:
                return self.create_result(
                    status="failed",
                    findings=[],
                    duration_seconds=duration_seconds,
                    error=(
                        f"Gitleaks output exceeded maximum limit of "
                        f"{self.max_output_bytes} bytes (received {len(report_text)} bytes)"
                    ),
                )

            stderr_text = stderr_data.decode("utf-8", errors="replace")
            safe_stderr = self._sanitize_error(stderr_text)

            # 9. Parse JSON Output
            # Gitleaks outputs a JSON list of matches: [ {...}, {...} ]
            trimmed_text = report_text.strip()
            if not trimmed_text:
                if process.returncode in (0, 1):
                    # Clean scan (zero leaks found)
                    return self.create_result(
                        status="success",
                        findings=[],
                        duration_seconds=duration_seconds,
                        error=None,
                    )
                else:
                    return self.create_result(
                        status="failed",
                        findings=[],
                        duration_seconds=duration_seconds,
                        error=safe_stderr or f"Gitleaks exited with error code {process.returncode}",
                    )

            try:
                data = json.loads(trimmed_text)
            except json.JSONDecodeError:
                error_msg = (
                    f"Malformed Gitleaks JSON output (exit code {process.returncode}): {safe_stderr}"
                    if safe_stderr
                    else f"Malformed Gitleaks JSON output: failed to decode JSON (exit code {process.returncode})"
                )
                return self.create_result(
                    status="failed",
                    findings=[],
                    duration_seconds=duration_seconds,
                    error=error_msg,
                )

            if isinstance(data, dict):
                raw_matches = data.get("results") or data.get("findings") or []
            elif isinstance(data, list):
                raw_matches = data
            else:
                return self.create_result(
                    status="failed",
                    findings=[],
                    duration_seconds=duration_seconds,
                    error="Malformed Gitleaks output: expected JSON array or object",
                )

            # 10. Extract, Sanitize, and Redact Findings
            findings: list[dict[str, Any]] = []
            for item in raw_matches:
                if isinstance(item, dict):
                    parsed = self._parse_finding(item, workspace_path)
                    if parsed is not None:
                        findings.append(parsed)

            # 11. Determine Execution Status
            # Note: Gitleaks exits with code 0 on no leaks, and exit code 1 when leaks are found.
            if process.returncode in (0, 1):
                status = "success"
                error = None
            else:
                if findings:
                    status = "partial"
                    error = safe_stderr or f"Gitleaks completed with findings and exit code {process.returncode}"
                else:
                    status = "failed"
                    error = safe_stderr or f"Gitleaks process exited with error code {process.returncode}"

            return self.create_result(
                status=status,
                findings=findings,
                duration_seconds=duration_seconds,
                error=error,
            )

        finally:
            # 12. Guaranteed Ephemeral Report Cleanup
            if report_file is not None and report_file.exists():
                try:
                    report_file.unlink()
                except OSError:
                    pass

    def _parse_finding(
        self,
        item: dict[str, Any],
        workspace_root: Path,
    ) -> dict[str, Any] | None:
        """
        Parse an individual Gitleaks match dictionary into a consistent raw finding.

        Enforces mandatory in-memory redaction of matched secret values and
        context evidence.
        """
        rule_id = str(item.get("RuleID") or item.get("rule_id") or "unknown-secret")
        prefixed_rule_id = f"gitleaks.{rule_id}"
        description = str(item.get("Description") or item.get("description") or rule_id)

        raw_filename = str(item.get("File") or item.get("file") or "")
        relative_path = self._sanitize_path(raw_filename, workspace_root)

        start_line = item.get("StartLine") or item.get("start_line")
        if not isinstance(start_line, int):
            start_line = None

        end_line = item.get("EndLine") or item.get("end_line")
        if not isinstance(end_line, int):
            end_line = start_line

        start_col = item.get("StartColumn") or item.get("start_column")
        if not isinstance(start_col, int):
            start_col = None

        end_col = item.get("EndColumn") or item.get("end_column")
        if not isinstance(end_col, int):
            end_col = None

        entropy = item.get("Entropy") or item.get("entropy")
        if isinstance(entropy, (int, float)):
            entropy = round(float(entropy), 2)
        else:
            entropy = None

        # Redaction enforcement
        raw_match = str(item.get("Match") or item.get("match") or "")
        raw_secret = str(item.get("Secret") or item.get("secret") or "")

        redacted_evidence = self._redact_secret_evidence(raw_match, raw_secret)
        severity = self._derive_severity(rule_id)

        metadata: dict[str, Any] = {
            "rule_id": rule_id,
            "description": description,
            "entropy": entropy,
            "fingerprint": item.get("Fingerprint") or item.get("fingerprint"),
            "tags": item.get("Tags") or item.get("tags") or [],
        }

        return {
            "scanner_name": self.name,
            "rule_id": prefixed_rule_id,
            "title": description,
            "severity": severity,
            "raw_category": "secrets",
            "file": relative_path,
            "line": start_line,
            "end_line": end_line,
            "col": start_col,
            "end_col": end_col,
            "evidence": redacted_evidence,
            "entropy": entropy,
            "metadata": metadata,
        }

    def _redact_secret_evidence(self, raw_match: str, raw_secret: str) -> str:
        """
        Redact the secret token from the evidence line and apply regex masking
        to guarantee no plaintext credentials enter findings.
        """
        if not raw_match:
            return "[REDACTED]"

        evidence = raw_match.strip()

        # 1. Direct secret token replacement
        if raw_secret and raw_secret.strip() and raw_secret in evidence:
            evidence = evidence.replace(raw_secret, "[REDACTED]")

        # 2. Known token format masking
        # AWS Access Keys
        evidence = re.sub(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b", r"\1****************", evidence)
        # GitHub Personal Access Tokens
        evidence = re.sub(r"\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b", r"\1_************************************", evidence)
        # Slack Webhooks
        evidence = re.sub(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+", "https://hooks.slack.com/services/[REDACTED]", evidence)
        # Private Key Headers
        evidence = re.sub(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", evidence)

        # 3. Bound length to at most 1000 characters
        return evidence[:1000]

    def _derive_severity(self, rule_id: str) -> str:
        """
        Derive vulnerability severity from the Gitleaks rule identifier.
        """
        lower = rule_id.lower()
        if any(key in lower for key in ("aws", "gcp", "azure", "private-key", "rsa", "ed25519", "ssh")):
            return "CRITICAL"
        if any(key in lower for key in ("github", "stripe", "slack", "openai", "token", "api-key", "jwt")):
            return "HIGH"
        return "MEDIUM"

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
