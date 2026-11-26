import json
import re
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

ScannerStatusType = Literal["success", "partial", "failed", "skipped"]


class ScannerStatus(str, Enum):
    """Execution status for an individual security scanner."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScannerExecutionResult(BaseModel):
    """Structured result model returned by every scanner execution."""

    scanner_name: str = Field(
        ...,
        min_length=1,
        description="Unique identifier of the scanner that generated this result.",
    )
    status: Literal["success", "partial", "failed", "skipped"] = Field(
        ...,
        description="Execution status of the scanner: success, partial, failed, or skipped.",
    )
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Raw finding dictionaries produced by the scanner before backend normalization.",
    )
    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Execution duration in seconds.",
    )
    error: str | None = Field(
        default=None,
        description="Nullable string containing a safe error description if execution was partial or failed.",
    )

    @property
    def is_successful(self) -> bool:
        """Return True if execution completed with success or partial findings."""
        return self.status in ("success", "partial")

    @property
    def has_findings(self) -> bool:
        """Return True if findings were discovered."""
        return len(self.findings) > 0


class ScannerError(Exception):
    """Base exception for all scanner execution errors."""

    pass


class ScannerTimeoutError(ScannerError):
    """Raised when scanner execution exceeds the configured timeout."""

    pass


class ScannerDependencyMissingError(ScannerError):
    """Raised when the scanner binary, container, or execution dependency is not found."""

    pass


class ScannerExecutionError(ScannerError):
    """Raised when a scanner process exits with an unexpected or unhandled error code."""

    pass


class BaseScanner(ABC):
    """
    Common abstract scanner interface for Thread Trace.

    Every scanner module must:
    1. Identify itself via the `name` property.
    2. Implement `scan(workspace)` returning a `ScannerExecutionResult`.
    3. Capture scanner-specific errors safely within its result.
    4. Not perform scan orchestration or directly mutate database/routes.
    5. Not transmit repository contents or unsanitized evidence to external services.
    6. Enforce parser, path sanitization, evidence bounding, and redaction boundaries.
    7. Guarantee zero uncaught exceptions through `safe_scan()`.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique identifier of the scanner (e.g., 'semgrep', 'bandit')."""
        raise NotImplementedError

    @property
    def scanner_name(self) -> str:
        """Alias for the scanner name property."""
        return self.name

    @abstractmethod
    async def scan(self, workspace: str) -> ScannerExecutionResult:
        """
        Execute the scanner against an isolated workspace directory.

        Args:
            workspace: Absolute path to the isolated directory containing target source code.

        Returns:
            ScannerExecutionResult: Structured result containing raw findings, status, duration, and error.
        """
        raise NotImplementedError

    async def safe_scan(self, workspace: str) -> ScannerExecutionResult:
        """
        Execute scan with complete fault-isolation guarantees.
        Catches any unexpected Python exceptions and safely wraps them in a failed
        ScannerExecutionResult, guaranteeing zero uncaught exceptions to the orchestrator.

        Args:
            workspace: Absolute path to the isolated directory containing target source code.

        Returns:
            ScannerExecutionResult: Result guaranteed not to raise unhandled exceptions.
        """
        try:
            return await self.scan(workspace)
        except Exception as exc:
            return self.create_result(
                status="failed",
                findings=[],
                duration_seconds=0.0,
                error=self.bound_error(f"Unexpected scanner exception in {self.name}: {exc}"),
            )

    def create_result(
        self,
        status: Literal["success", "partial", "failed", "skipped"],
        findings: list[dict[str, Any]] | None = None,
        duration_seconds: float = 0.0,
        error: str | None = None,
    ) -> ScannerExecutionResult:
        """
        Helper method to construct a ScannerExecutionResult identified by this scanner.

        Args:
            status: One of 'success', 'partial', 'failed', or 'skipped'.
            findings: List of raw finding dictionaries produced by the scanner.
            duration_seconds: Execution duration in seconds.
            error: Optional safe error description.

        Returns:
            ScannerExecutionResult: Structured result populated with this scanner's identity.
        """
        return ScannerExecutionResult(
            scanner_name=self.name,
            status=status,
            findings=findings or [],
            duration_seconds=duration_seconds,
            error=self.bound_error(error),
        )

    @staticmethod
    def sanitize_path(raw_path: str, workspace_path: Path | str) -> str:
        """
        Sanitize and validate a file path, ensuring it stays within workspace boundaries.
        Returns a normalized POSIX relative path, or '[REJECTED_OUTSIDE_WORKSPACE]'.
        """
        if not raw_path:
            return "[UNKNOWN_PATH]"
        try:
            ws_resolved = Path(workspace_path).resolve()
            p = Path(raw_path)
            if p.is_absolute():
                resolved = p.resolve()
            else:
                resolved = (ws_resolved / p).resolve()

            try:
                rel = resolved.relative_to(ws_resolved)
                norm = rel.as_posix()
                if norm == ".":
                    return p.name
                return norm
            except ValueError:
                return "[REJECTED_OUTSIDE_WORKSPACE]"
        except Exception:
            return "[INVALID_PATH]"

    @staticmethod
    def bound_evidence(evidence: str, max_chars: int = 1000) -> str:
        """
        Bound evidence length to prevent memory bloat, database saturation, or API payload bloat.
        Truncates with trailing ellipsis if length exceeds max_chars.
        """
        if not evidence:
            return ""
        if len(evidence) <= max_chars:
            return evidence
        return evidence[: max_chars - 3] + "..."

    @staticmethod
    def redact_evidence(evidence: str) -> str:
        """
        Mandatory in-memory credential redaction.
        Strips or masks API keys, tokens, and private keys so they never enter findings or AI context.
        """
        if not evidence:
            return ""

        redacted = evidence

        # AWS Access Key ID
        redacted = re.sub(
            r"\b(AKIA[0-9A-Z]{16})\b",
            r"AKIA****************",
            redacted,
        )

        # GitHub Personal Access Token
        redacted = re.sub(
            r"\b(gh[pousr]_[0-9a-zA-Z]{36})\b",
            r"[REDACTED_GITHUB_TOKEN]",
            redacted,
        )

        # Private Keys
        redacted = re.sub(
            r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----",
            r"[REDACTED_PRIVATE_KEY]",
            redacted,
        )

        # Slack Webhook URLs
        redacted = re.sub(
            r"https://hooks\.slack\.com/services/[A-Za-z0-9+/_-]+",
            r"https://hooks.slack.com/services/[REDACTED]",
            redacted,
        )

        # Bearer Tokens
        redacted = re.sub(
            r"(Bearer\s+)[a-zA-Z0-9_\-\.]{20,}",
            r"\1[REDACTED_BEARER_TOKEN]",
            redacted,
            flags=re.IGNORECASE,
        )

        return redacted

    @staticmethod
    def bound_error(error: str | None, max_chars: int = 1000) -> str | None:
        """Sanitize and bound error messages to prevent leakage of secrets or process dumps."""
        if not error:
            return None
        trimmed = error.strip()
        if not trimmed:
            return None
        if len(trimmed) > max_chars:
            return trimmed[: max_chars - 3] + "..."
        return trimmed

    @staticmethod
    def parse_json_safely(raw_text: str) -> Any | None:
        """
        Safely parse JSON from tool stdout/stderr.
        Handles CLI banner text, warnings, or preamble before/after the JSON payload.
        """
        if not raw_text or not raw_text.strip():
            return None

        stripped = raw_text.strip()
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON object {...}
        obj_start = stripped.find("{")
        obj_end = stripped.rfind("}")
        if obj_start != -1 and obj_end != -1 and obj_end > obj_start:
            try:
                return json.loads(stripped[obj_start : obj_end + 1])
            except json.JSONDecodeError:
                pass

        # Try extracting JSON array [...]
        arr_start = stripped.find("[")
        arr_end = stripped.rfind("]")
        if arr_start != -1 and arr_end != -1 and arr_end > arr_start:
            try:
                return json.loads(stripped[arr_start : arr_end + 1])
            except json.JSONDecodeError:
                pass

        return None


def aggregate_scanner_statuses(
    results: list[ScannerExecutionResult],
) -> Literal["success", "partial", "failed", "skipped"]:
    """
    Deterministically aggregate multiple scanner execution results into an overall job status.

    Aggregation Rules:
    - If results is empty -> 'skipped'
    - If all results are 'skipped' -> 'skipped'
    - If all results are 'failed' -> 'failed'
    - If any scanner is 'failed' or 'partial' while at least one is 'success' -> 'partial'
    - If all executed scanners are 'success' (with or without 'skipped' scanners) -> 'success'
    """
    if not results:
        return "skipped"

    statuses = [r.status for r in results]

    if all(s == "skipped" for s in statuses):
        return "skipped"

    if all(s == "failed" for s in statuses):
        return "failed"

    has_success = any(s == "success" for s in statuses)
    has_partial = any(s == "partial" for s in statuses)
    has_failed = any(s == "failed" for s in statuses)

    if has_failed or has_partial:
        return "partial"

    if has_success:
        return "success"

    return "skipped"
