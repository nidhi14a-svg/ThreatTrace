# Scanner Interface Specification

- **Document:** `specs/SCANNER_INTERFACE_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator:** Dev B (Backend Developer)
- **Implementation File:** `backend/app/scanners/base_scanner.py`
- **Task Reference:** Phase 2, Task 2.1 — Scanner Interface
- **Status:** Approved Specification & Implementation
- **Version:** 2.0.0

---

## 1. Executive Summary & Purpose

Task 2.1 establishes the foundational interface contract governing all security scanners in Thread Trace. The objective is to decouple scanner execution from backend scan orchestration, database persistence, and API transport.

By enforcing a common abstract base class (`BaseScanner`) and a validated, structured execution result (`ScannerExecutionResult`), Thread Trace guarantees that:
1. Each security scanner runs as an independent, modular component.
2. Individual scanner failures, syntax errors, or timeouts are captured cleanly and isolated within that scanner's result.
3. The overall scan orchestration workflow never terminates prematurely due to a single tool's failure.
4. Scanners produce **raw finding dictionaries**, preserving raw tool telemetry and leaving normalization to the backend pipeline.
5. Scanners remain completely unprivileged, stateless, and isolated from external AI APIs or database models.

---

## 2. Structured Result Model: `ScannerExecutionResult`

Every scanner invocation must return an instance of `ScannerExecutionResult` implemented in `backend/app/scanners/base_scanner.py`.

### 2.1 Field Schema & Types

| Field Name | Type | Constraint | Description |
|---|---|---|---|
| `scanner_name` | `str` | `min_length=1` | Unique identifier of the scanner module (e.g., `'semgrep'`, `'bandit'`). |
| `status` | `Literal["success", "partial", "failed", "skipped"]` | Strict 4-value literal | Execution outcome of the tool. |
| `findings` | `list[dict[str, Any]]` | Default: `[]` | List of raw, un-normalized finding dictionaries emitted by the tool parser. |
| `duration_seconds` | `float` | `ge=0.0`, Default: `0.0` | Wall-clock execution duration in seconds. |
| `error` | `str \| None` | Default: `None` | Nullable string containing a safe, sanitized error or diagnostic description. |

### 2.2 Pydantic Definition
```python
class ScannerExecutionResult(BaseModel):
    scanner_name: str = Field(..., min_length=1, description="Unique identifier of the scanner")
    status: Literal["success", "partial", "failed", "skipped"] = Field(..., description="Execution status")
    findings: list[dict[str, Any]] = Field(default_factory=list, description="Raw finding dictionaries")
    duration_seconds: float = Field(default=0.0, ge=0.0, description="Execution duration in seconds")
    error: str | None = Field(default=None, description="Safe error description if partial or failed")
```

---

## 3. Abstract Scanner Contract: `BaseScanner`

All scanner adapters must inherit from `BaseScanner` (`backend/app/scanners/base_scanner.py`).

### 3.1 Interface Definition
```python
class BaseScanner(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique identifier of the scanner."""
        raise NotImplementedError

    @property
    def scanner_name(self) -> str:
        """Alias for the name property."""
        return self.name

    @abstractmethod
    async def scan(self, workspace: str) -> ScannerExecutionResult:
        """Execute scanner against an isolated workspace directory."""
        raise NotImplementedError

    def create_result(
        self,
        status: Literal["success", "partial", "failed", "skipped"],
        findings: list[dict[str, Any]] | None = None,
        duration_seconds: float = 0.0,
        error: str | None = None,
    ) -> ScannerExecutionResult:
        """Helper to construct a ScannerExecutionResult identified by this scanner."""
        return ScannerExecutionResult(
            scanner_name=self.name,
            status=status,
            findings=findings or [],
            duration_seconds=duration_seconds,
            error=error,
        )
```

### 3.2 Scanner Implementation Invariants
1. **Independence:** Scanner classes must not import or depend upon each other.
2. **Self-Identification:** Each scanner must explicitly identify its `name` (e.g., `'semgrep'`, `'bandit'`).
3. **Structured Return:** Scanners must never return bare lists, primitives, or unhandled exceptions; `scan()` must always return a `ScannerExecutionResult`.
4. **Internal Error Capture:** Any internal subprocess failure, parser error, or timeout must be caught by the scanner adapter and returned with `status="failed"` or `status="partial"`.
5. **No Orchestration:** Scanners must not orchestrate multi-tool workflows, schedule jobs, or invoke sibling scanners.
6. **No API / DB Direct Calls:** Scanners must never import FastAPI routers, Motor database clients, or write directly to MongoDB.
7. **No AI Egress:** Scanners must never transmit repository files or unredacted code snippets to third-party AI APIs.

---

## 4. Failure Semantics & Status States

Thread Trace scanners operate across four mutually exclusive execution statuses:

| Status | Meaning | Conditions | Findings State |
|---|---|---|---|
| `success` | Complete Success | Scanner finished cleanly, all files analyzed, zero unrecoverable errors. | Complete raw findings list (can be empty if no bugs found). |
| `partial` | Partial / Degraded | Scanner finished with recoverable warnings (e.g., 1 file had syntax error, remainder scanned). | Partial raw findings list; `error` describes skipped files. |
| `failed` | Execution Failed | Scanner crashed, binary was missing, timed out, or exited with an unrecoverable code. | Empty findings list (`[]`); `error` contains safe error message. |
| `skipped` | Intentionally Skipped | Workspace contains no files compatible with the scanner (e.g., no Python files for Bandit). | Empty findings list (`[]`); `error` is `None`. |

### 4.1 Pipeline Isolation Guarantee
```
                       +----------------------------------+
                       | Dev B Orchestrator (scan_service)|
                       +----------------------------------+
                          |        |           |        |
             +------------+        |           |        +------------+
             |                     |           |                     |
             v                     v           v                     v
      [ SemgrepScanner ]    [ BanditScanner ] [ SecretsScanner ]  [ DependencyScanner ]
      Status: SUCCESS       Status: FAILED    Status: SUCCESS     Status: SKIPPED
      Findings: 12          Findings: 0       Findings: 3         Findings: 0
      Error: None           Error: "Timeout"  Error: None         Error: None
             |                     |           |                     |
             +---------------------+-----------+---------------------+
                                   |
                                   v
             Aggregated Execution: Partial Success (15 total findings)
             Pipeline did NOT crash; Bandit failure is logged gracefully.
```

---

## 5. Compatibility Analysis with Dev B's Shared Finding Schema

### 5.1 Raw Findings vs. Normalized Findings
- **Crucial Distinction:** `ScannerExecutionResult.findings` contains **raw scanner finding dictionaries** directly from the tool's output parser (e.g., Semgrep JSON match objects, Bandit issue dictionaries).
- **Backend Normalization Ownership:** Dev B's backend orchestrator (`scan_service.py`) owns mapping raw dictionaries into the shared `Finding` schema ([backend/app/schemas/finding.py](file:///c:/Users/nidhi/Desktop/mini/backend/app/schemas/finding.py)).
- **Decoupling Benefit:** Because scanners emit raw dictionaries, changes to the normalized schema do not break scanner adapter execution contracts.

### 5.2 Dev B Approved Schema Evolution
Dev B has approved the following strict constraints for the shared `Finding` schema:
1. **Approved Domain Literals (10 values):**
   ```python
   Literal[
       "injection",
       "authentication",
       "authorization",
       "cryptography",
       "secrets",
       "dependencies",
       "configuration",
       "input_validation",
       "logging",
       "other",
   ]
   ```
2. **Approved Confidence Literals (3 values):**
   ```python
   Literal["low", "medium", "high"]
   ```
3. **Optional Raw Category Field:**
   ```python
   raw_category: str | None = None
   ```
   *Purpose:* Preserves the scanner's native rule classification (e.g., `"B501"` or `"owasp-a1"`) alongside the canonical domain.

### 5.3 Audit of Existing `backend/app/schemas/finding.py` & Identified Gaps
Dev C inspected the current `Finding` model authored by Dev B:
```python
class Finding(BaseModel):
    id: str
    domain: str                                                 # Gap: Currently open string, not 10-value Literal
    rule_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    file: str
    line: int | None = None
    evidence: str
    confidence: str                                             # Gap: Currently open string, not Literal["low", "medium", "high"]
    explanation: str | None = None
    recommendation: str | None = None
    tool: str
    # Gap: raw_category is not yet defined
```

**Identified Compatibility Considerations for Dev B:**
1. In [backend/tests/test_findings.py](file:///c:/Users/nidhi/Desktop/mini/backend/tests/test_findings.py), line 7 currently sets `domain="Secrets Management"`.
2. When Dev B updates `domain` to the approved 10-value literal, `"Secrets Management"` must be updated to `"secrets"`, otherwise existing tests will fail validation.
3. Dev C has **not modified** `backend/app/schemas/finding.py` in accordance with ownership rules. Dev C reports these findings for Dev B's scheduled update.

---

## 6. Verification & Test Coverage

Task 2.1 is verified by the focused test suite at [backend/tests/test_scanner_interface.py](file:///c:/Users/nidhi/Desktop/mini/backend/tests/test_scanner_interface.py):
- `test_valid_scanner_execution_result_creation`: Validates creation and serialization.
- `test_all_four_status_values_accepted`: Validates `'success'`, `'partial'`, `'failed'`, `'skipped'`.
- `test_scanner_status_enum_compatibility`: Validates `ScannerStatus` enum equality.
- `test_invalid_status_values_rejected`: Validates rejection of invalid strings/types via `ValidationError`.
- `test_empty_findings_supported`: Validates default and explicit empty list support.
- `test_raw_findings_contain_dictionaries`: Validates raw dictionary items and rejection of non-dict items.
- `test_nullable_errors_work_correctly`: Validates `error=None`, omission, and string descriptions.
- `test_duration_seconds_validation`: Validates non-negative float validation.
- `test_scanner_name_validation`: Validates non-empty string requirement.
- `test_scanner_subclass_cannot_instantiate_without_required_methods`: Validates abstract method enforcement (`TypeError`).
- `test_scanner_subclass_return_contract_is_consistent`: Validates async `scan()` execution and return types.
- `test_scanner_failure_does_not_crash_pipeline`: Validates safe error containment during scanner failure.
- `test_scanner_partial_status_reporting`: Validates partial recovery and diagnostic error reporting.
- `test_scanner_skipped_status_reporting`: Validates skipped status when target files are absent.
- `test_existing_scanner_stubs_satisfy_base_scanner_interface`: Validates `SemgrepScanner`, `BanditScanner`, `SecretsScanner`, and `DependencyScanner` all instantiate and return `ScannerExecutionResult`.
