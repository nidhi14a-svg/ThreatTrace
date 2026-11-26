import pytest
from pydantic import ValidationError

from app.scanners.bandit_scanner import BanditScanner
from app.scanners.base_scanner import (
    BaseScanner,
    ScannerDependencyMissingError,
    ScannerError,
    ScannerExecutionError,
    ScannerExecutionResult,
    ScannerStatus,
    ScannerTimeoutError,
)
from app.scanners.dependency_scanner import DependencyScanner
from app.scanners.secrets_scanner import SecretsScanner
from app.scanners.semgrep_scanner import SemgrepScanner


# ============================================================================
# 1. ScannerExecutionResult Creation & Field Verification
# ============================================================================


def test_valid_scanner_execution_result_creation():
    """Verify that a valid ScannerExecutionResult can be created with all fields."""
    raw_finding = {
        "check_id": "semgrep.sql-injection",
        "path": "app/routes.py",
        "start": {"line": 42, "col": 5},
        "extra": {"message": "SQL injection detected"},
    }
    result = ScannerExecutionResult(
        scanner_name="semgrep",
        status="success",
        findings=[raw_finding],
        duration_seconds=1.45,
        error=None,
    )

    assert result.scanner_name == "semgrep"
    assert result.status == "success"
    assert len(result.findings) == 1
    assert result.findings[0]["check_id"] == "semgrep.sql-injection"
    assert result.duration_seconds == 1.45
    assert result.error is None

    dumped = result.model_dump()
    assert dumped["scanner_name"] == "semgrep"
    assert dumped["status"] == "success"
    assert dumped["duration_seconds"] == 1.45


# ============================================================================
# 2. Status Values Verification (All 4 Accepted)
# ============================================================================


@pytest.mark.parametrize("status_value", ["success", "partial", "failed", "skipped"])
def test_all_four_status_values_accepted(status_value):
    """Verify that all four required status values are accepted."""
    result = ScannerExecutionResult(
        scanner_name="bandit",
        status=status_value,
        findings=[],
        duration_seconds=0.1,
    )
    assert result.status == status_value


def test_scanner_status_enum_compatibility():
    """Verify that ScannerStatus enum members match the literal string values."""
    assert ScannerStatus.SUCCESS == "success"
    assert ScannerStatus.PARTIAL == "partial"
    assert ScannerStatus.FAILED == "failed"
    assert ScannerStatus.SKIPPED == "skipped"

    for enum_member in ScannerStatus:
        result = ScannerExecutionResult(
            scanner_name="test_scanner",
            status=enum_member,
        )
        assert result.status == enum_member.value


# ============================================================================
# 3. Invalid Status Values Rejection
# ============================================================================


@pytest.mark.parametrize(
    "invalid_status",
    ["error", "unknown", "completed", "running", "PENDING", "", "SUCCESS", 123],
)
def test_invalid_status_values_rejected(invalid_status):
    """Verify that any status outside the four permitted values is rejected."""
    with pytest.raises(ValidationError):
        ScannerExecutionResult(
            scanner_name="test_scanner",
            status=invalid_status,  # type: ignore[arg-type]
        )


# ============================================================================
# 4. Empty Findings Support
# ============================================================================


def test_empty_findings_supported():
    """Verify that empty findings list is supported by default and explicitly."""
    result_default = ScannerExecutionResult(
        scanner_name="secrets",
        status="success",
    )
    assert result_default.findings == []

    result_explicit = ScannerExecutionResult(
        scanner_name="secrets",
        status="success",
        findings=[],
    )
    assert result_explicit.findings == []


def test_raw_findings_contain_dictionaries():
    """Verify that findings must contain raw dictionaries and rejects non-dict items."""
    valid_findings = [
        {"tool": "semgrep", "cwe": "CWE-89"},
        {"tool": "bandit", "issue_severity": "HIGH"},
    ]
    result = ScannerExecutionResult(
        scanner_name="multi_tool",
        status="success",
        findings=valid_findings,
    )
    assert len(result.findings) == 2

    # Findings with non-dict items must be rejected
    with pytest.raises(ValidationError):
        ScannerExecutionResult(
            scanner_name="invalid_findings_tool",
            status="success",
            findings=["not_a_dict"],  # type: ignore[list-item]
        )


# ============================================================================
# 5. Nullable Error Handling
# ============================================================================


def test_nullable_errors_work_correctly():
    """Verify that error can be None, omitted, or a descriptive string."""
    result_none = ScannerExecutionResult(
        scanner_name="osv",
        status="success",
        error=None,
    )
    assert result_none.error is None

    result_omitted = ScannerExecutionResult(
        scanner_name="osv",
        status="success",
    )
    assert result_omitted.error is None

    result_with_error = ScannerExecutionResult(
        scanner_name="osv",
        status="failed",
        error="Dependency manifest could not be parsed: invalid YAML syntax",
    )
    assert result_with_error.error == "Dependency manifest could not be parsed: invalid YAML syntax"


# ============================================================================
# 6. Additional Field Constraints (duration, scanner_name)
# ============================================================================


def test_duration_seconds_validation():
    """Verify non-negative duration validation."""
    result = ScannerExecutionResult(
        scanner_name="tool",
        status="success",
        duration_seconds=0.0,
    )
    assert result.duration_seconds == 0.0

    with pytest.raises(ValidationError):
        ScannerExecutionResult(
            scanner_name="tool",
            status="success",
            duration_seconds=-0.5,
        )


def test_scanner_name_validation():
    """Verify scanner_name cannot be empty."""
    with pytest.raises(ValidationError):
        ScannerExecutionResult(
            scanner_name="",
            status="success",
        )


# ============================================================================
# 7. Scanner Subclasses Must Implement Required Methods
# ============================================================================


def test_scanner_subclass_cannot_instantiate_without_required_methods():
    """Verify that BaseScanner subclasses must implement name and scan."""

    class IncompleteScannerMissingBoth(BaseScanner):
        pass

    with pytest.raises(TypeError):
        IncompleteScannerMissingBoth()  # type: ignore[abstract]

    class IncompleteScannerMissingScan(BaseScanner):
        name = "test_scanner"

    with pytest.raises(TypeError):
        IncompleteScannerMissingScan()  # type: ignore[abstract]

    class IncompleteScannerMissingName(BaseScanner):
        async def scan(self, workspace: str) -> ScannerExecutionResult:
            return ScannerExecutionResult(scanner_name="temp", status="success")

    with pytest.raises(TypeError):
        IncompleteScannerMissingName()  # type: ignore[abstract]


# ============================================================================
# 8. Consistent Return Contract & Subclass Execution
# ============================================================================


@pytest.mark.anyio
async def test_scanner_subclass_return_contract_is_consistent():
    """Verify that an implemented scanner subclass returns a valid ScannerExecutionResult."""

    class TestMockScanner(BaseScanner):
        name = "mock_scanner"

        async def scan(self, workspace: str) -> ScannerExecutionResult:
            raw_findings = [
                {"id": "RAW-001", "file": f"{workspace}/test.py", "severity": "HIGH"}
            ]
            return self.create_result(
                status="success",
                findings=raw_findings,
                duration_seconds=0.25,
            )

    scanner = TestMockScanner()
    assert scanner.name == "mock_scanner"
    assert scanner.scanner_name == "mock_scanner"

    result = await scanner.scan("/workspace/sample")
    assert isinstance(result, ScannerExecutionResult)
    assert result.scanner_name == "mock_scanner"
    assert result.status == "success"
    assert len(result.findings) == 1
    assert result.findings[0]["id"] == "RAW-001"
    assert result.duration_seconds == 0.25
    assert result.error is None


@pytest.mark.anyio
async def test_scanner_failure_does_not_crash_pipeline():
    """Verify that scanner failures are captured safely in ScannerExecutionResult."""

    class FailingScanner(BaseScanner):
        name = "failing_scanner"

        async def scan(self, workspace: str) -> ScannerExecutionResult:
            try:
                raise ScannerTimeoutError("Process killed after 60s timeout")
            except ScannerError as exc:
                return self.create_result(
                    status="failed",
                    findings=[],
                    duration_seconds=60.0,
                    error=str(exc),
                )

    scanner = FailingScanner()
    result = await scanner.scan("/workspace/slow_project")

    assert isinstance(result, ScannerExecutionResult)
    assert result.status == "failed"
    assert result.scanner_name == "failing_scanner"
    assert "timeout" in result.error.lower()
    assert result.findings == []


@pytest.mark.anyio
async def test_scanner_partial_status_reporting():
    """Verify that recoverable scanner warnings/errors report status='partial'."""

    class PartialScanner(BaseScanner):
        name = "partial_scanner"

        async def scan(self, workspace: str) -> ScannerExecutionResult:
            findings = [{"id": "PARTIAL-001", "file": "main.py"}]
            return self.create_result(
                status="partial",
                findings=findings,
                duration_seconds=1.2,
                error="1 file could not be parsed due to Python syntax error (app/legacy.py)",
            )

    scanner = PartialScanner()
    result = await scanner.scan("/workspace/mixed_project")

    assert result.status == "partial"
    assert len(result.findings) == 1
    assert "syntax error" in result.error


@pytest.mark.anyio
async def test_scanner_skipped_status_reporting():
    """Verify that a scanner that has no relevant files to scan reports status='skipped'."""

    class SkippedScanner(BaseScanner):
        name = "skipped_scanner"

        async def scan(self, workspace: str) -> ScannerExecutionResult:
            return self.create_result(
                status="skipped",
                findings=[],
                duration_seconds=0.01,
                error=None,
            )

    scanner = SkippedScanner()
    result = await scanner.scan("/workspace/empty_project")

    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None


# ============================================================================
# 9. Existing Scanner Stubs Conformance
# ============================================================================


@pytest.mark.anyio
@pytest.mark.parametrize(
    "scanner_class,expected_name",
    [
        (SemgrepScanner, "semgrep"),
        (BanditScanner, "bandit"),
        (SecretsScanner, "secrets"),
        (DependencyScanner, "dependency"),
    ],
)
async def test_existing_scanner_stubs_satisfy_base_scanner_interface(
    scanner_class, expected_name
):
    """Verify that all existing scanner stubs instantiate and return ScannerExecutionResult."""
    scanner = scanner_class()
    assert scanner.name == expected_name
    assert scanner.scanner_name == expected_name

    result = await scanner.scan("/tmp/test_workspace")
    assert isinstance(result, ScannerExecutionResult)
    assert result.scanner_name == expected_name
    assert result.status == "skipped"
    assert result.findings == []
    assert result.error is None
