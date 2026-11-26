# Service Interfaces Specification — Dev C (Cybersecurity & Scanner Modules)

- **Document:** `docs/SERVICE_INTERFACES_DEV_C.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator:** Dev B (Backend Developer)
- **Status:** Approved Interface Specification (Phase 1)
- **Version:** 1.0.0

---

## 1. Executive Summary & Purpose

This document defines the formal architectural and interface contracts between the **scanner modules** (authored by Dev C) and the **backend scan orchestration and API services** (authored by Dev B).

Adherence to this contract ensures:
1. **Loose Coupling:** The backend orchestrator treats all scanners uniformly via the `BaseScanner` abstraction without coupling to tool-specific CLI invocations.
2. **Defensive Error Handling:** Individual scanner crashes or timeouts do not disrupt other scanner executions or compromise API reliability.
3. **Strict AI Boundaries:** External AI integration receives only sanitized, redacted finding summaries, never raw repositories or credentials.
4. **Clean Ownership:** Clear division of responsibilities prevents merge conflicts, redundant code, or architectural divergence between Dev B and Dev C.

*Phase 1 Rule:* This document specifies the planned interface contract. Concrete scanner implementations will be built in Phase 2.

---

## 2. BaseScanner Interface Contract

All scanner adapters in `backend/app/scanners/` inherit from the common abstract base class `BaseScanner` located at `backend/app/scanners/base_scanner.py`.

### 2.1 Abstract Base Class Definition
```python
from abc import ABC, abstractmethod
from enum import Enum
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
    scanner_name: str = Field(..., min_length=1, description="Unique identifier of the scanner")
    status: Literal["success", "partial", "failed", "skipped"] = Field(..., description="Execution status")
    findings: list[dict[str, Any]] = Field(default_factory=list, description="Raw finding dictionaries")
    duration_seconds: float = Field(default=0.0, ge=0.0, description="Execution duration in seconds")
    error: str | None = Field(default=None, description="Safe error description if partial or failed")


class BaseScanner(ABC):
    """Abstract base class for all Thread Trace security scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier of the scanner (e.g., 'semgrep', 'bandit')."""
        raise NotImplementedError

    @property
    def scanner_name(self) -> str:
        """Alias for name property."""
        return self.name

    @abstractmethod
    async def scan(self, workspace: str) -> ScannerExecutionResult:
        """
        Execute security scan against an isolated workspace directory.

        Args:
            workspace: Absolute path to the isolated directory containing extracted source code.

        Returns:
            ScannerExecutionResult: Structured result containing raw findings, status, duration, and error.
        """
        raise NotImplementedError

    def create_result(
        self,
        status: Literal["success", "partial", "failed", "skipped"],
        findings: list[dict[str, Any]] | None = None,
        duration_seconds: float = 0.0,
        error: str | None = None,
    ) -> ScannerExecutionResult:
        """Helper method to construct a ScannerExecutionResult identified by this scanner."""
        return ScannerExecutionResult(
            scanner_name=self.name,
            status=status,
            findings=findings or [],
            duration_seconds=duration_seconds,
            error=error,
        )
```

---

## 3. Scanner Input Requirements

### 3.1 Input Parameters
- **`workspace` (str):**
  - Absolute filesystem path to the extracted source code directory (e.g., `/tmp/thread-trace/workspaces/<scan_id>/`).
  - Guaranteed by Dev B's extraction service to be sanitized, verified, and free of Zip Slip traversal attacks.
  - Mounted into scanner environments strictly as **read-only** (`:ro`).
- **Scan Configuration Options (Optional Kwargs / Context):**
  - `timeout_seconds: int = 60` — Per-scanner execution timeout.
  - `custom_rules_dir: str | None = None` — Optional path to custom YAML/AST rule packs.
  - `excluded_paths: list[str] = []` — List of directories to skip (e.g., `tests`, `node_modules`).

---

## 4. Scanner Output Structure & Normalized Finding Contract

### 4.1 Output Contract
Each call to `scanner.scan(workspace)` must return a Python list of dictionaries:
`list[dict[str, Any]]`

Each dictionary in this list must be directly instantiable into Dev B's canonical `Finding` Pydantic model (`backend/app/schemas/finding.py`):

```python
finding = Finding(**raw_dict)
```

### 4.2 Exact Field Alignment Table
| Field Name | Type | Requirement | Constraints / Formatting |
|---|---|---|---|
| `id` | `str` | Required | Unique ID format: `find_<uuid4_hex>` |
| `domain` | `str` | Required | Exactly one of the 5 canonical domain titles |
| `rule_id` | `str` | Required | Prefixed rule identifier (e.g., `bandit.B501`, `semgrep.xss`) |
| `title` | `str` | Required | Human-readable title (max 150 chars) |
| `severity` | `Literal["critical", "high", "medium", "low"]` | Required | Strictly lowercase severity tier |
| `file` | `str` | Required | Relative path within workspace, forward slashes (`/`), no `../` |
| `line` | `int | None` | Optional | 1-indexed positive int, or `None` for package-level findings |
| `evidence` | `str` | Required | Code snippet or advisory statement, **strictly redacted**, max 1000 chars |
| `confidence` | `str` | Required | Normalized value: `"high"`, `"medium"`, or `"low"` |
| `explanation` | `str | None` | Optional | Initialized to `None` or tool doc; enriched by AI service |
| `recommendation` | `str | None` | Optional | Initialized to default mitigation or `None`; enriched by AI |
| `tool` | `str` | Required | Tool name: `"semgrep"`, `"bandit"`, `"gitleaks"`, `"osv-scanner"`, `"custom-rules"` |

---

## 5. Scanner Execution Status

The scan lifecycle tracks individual tool execution via `ScannerStatus`:

1. **`PENDING`:** Scanner job queued in orchestrator.
2. **`RUNNING`:** Scanner process actively executing against workspace.
3. **`SUCCESS`:** Scanner completed successfully, findings parsed and normalized.
4. **`PARTIAL_SUCCESS`:** Scanner completed with warnings on certain files, but returned valid findings for the remainder.
5. **`FAILED`:** Scanner failed to execute due to binary crash, non-zero exit without output, or syntax error.
6. **`TIMEOUT`:** Scanner exceeded maximum execution duration (`SCANNER_TIMEOUT_SECONDS`) and was terminated.
7. **`SKIPPED`:** Scanner skipped because workspace contains no compatible files (e.g., skipping Bandit when no Python files exist).

---

## 6. Error-Handling Contract & Resilience

Scanners must fail gracefully without bringing down the FastAPI application or blocking other scanners:

```
                  +--------------------------------+
                  | Dev B Orchestrator (scan_all)  |
                  +--------------------------------+
                      |         |            |
         +------------+         |            +-------------+
         |                      |                          |
         v                      v                          v
  [ Semgrep Scanner ]   [ Bandit Scanner ]       [ Gitleaks Scanner ]
     (Completed)           (Syntax Error)             (Completed)
         |                      |                          |
         v                      v                          v
   Status: SUCCESS       Status: FAILED             Status: SUCCESS
   12 Findings           0 Findings, Log Error      3 Findings
         |                      |                          |
         +----------------------+--------------------------+
                                |
                                v
               Aggregated Scan Result: PARTIAL_SUCCESS
               15 Total Normalized Findings
               1 Logged Tool Failure (Bandit)
```

### 6.1 Exception Hierarchy
Dev C provides standard exception classes in `backend/app/scanners/base_scanner.py`:
- `ScannerError(Exception)`: Base exception for all scanner failures.
- `ScannerTimeoutError(ScannerError)`: Raised when a scanner exceeds its timeout.
- `ScannerDependencyMissingError(ScannerError)`: Raised if the scanner CLI or container cannot be reached.
- `ScannerExecutionError(ScannerError)`: Raised when a scanner exits with an unexpected fatal error code.

### 6.2 Orchestration Resilience Guarantee
- Dev B's orchestration service wraps each scanner call in an isolated exception handler.
- If Bandit raises a `ScannerExecutionError` (e.g., due to unparseable Python 2 syntax in target code), the orchestrator logs the warning, marks Bandit's status as `FAILED`, and continues collecting results from Semgrep, Gitleaks, and OSV-Scanner.

---

## 7. Timeout & Resource-Limit Settings

Interface settings must integrate with `backend/app/core/config.py` using environment variable overrides:

| Config Parameter | Default Value | Description |
|---|---|---|
| `SCANNER_TIMEOUT_SECONDS` | `60` | Hard timeout per scanner module. |
| `SCANNER_MEMORY_LIMIT` | `"1.5g"` | Max container memory allocated per scanner instance. |
| `SCANNER_CPU_LIMIT` | `"1.5"` | Max CPU cores allocated per scanner instance. |
| `SCANNER_PIDS_LIMIT` | `100` | Process limit preventing fork bombs. |
| `SCANNER_MAX_OUTPUT_BYTES` | `10485760` (10 MB) | Max stdout JSON payload parsed by scanner adapter. |

---

## 8. AI Context Boundary & Sanitization Contract

External AI models (e.g., Gemini, OpenAI, Claude) used in Thread Trace for explanation and remediation must be strictly isolated from sensitive source code:

### 8.1 Forbidden AI Payloads
Under NO circumstances may any scanner or backend service transmit:
- Entire source-code files or raw repository directory archives.
- Unredacted credentials, API keys, passwords, or connection strings.
- Internal host paths, environment variables, or database connection strings.

### 8.2 Sanitized AI Payload Schema
When Dev B's `ai_service.py` invokes the AI model, it must construct the prompt context strictly from the normalized finding metadata:

```json
{
  "finding_id": "find_a1b2c3d4e5f67890",
  "domain": "Web Application Security",
  "rule_id": "semgrep.python.fastapi.security.sql-injection-format-string",
  "title": "SQL Query Formatted with Untrusted Input",
  "severity": "high",
  "file": "backend/app/api/routes/users.py",
  "line": 42,
  "sanitized_evidence": "query = f\"SELECT * FROM users WHERE email = '{user_input}'\"",
  "tool": "semgrep"
}
```

AI generation is strictly additive:
- Output from AI populates `finding.explanation` and `finding.recommendation`.
- AI output CANNOT alter the verified scanner evidence, severity, rule ID, or file location.

---

## 9. Ownership Boundaries (Dev B vs. Dev C)

To ensure clarity and prevent team conflicts:

| Component / Subsystem | Dev B (Backend Developer) | Dev C (Cybersecurity & DevOps) |
|---|---|---|
| **Archive Ingestion & Extraction** | Implements `extraction_service.py` & upload API | Defines security limits (`specs/ZIP_ARCHIVE_SECURITY_SPEC.md`) & tests |
| **Finding Schema (`finding.py`)** | Owns Pydantic model definition | Defines normalization standard & mapping rules |
| **Scanner Interface (`base_scanner.py`)** | Imports and calls `scanner.scan()` | Implements `BaseScanner` interface & exceptions |
| **Scanner Adapters (`app/scanners/*`)** | Consumes normalized output | Implements Semgrep, Bandit, Gitleaks, OSV, Custom adapters |
| **Orchestration (`scan_service.py`)** | Implements asynchronous scan orchestrator | Provides concurrency & resource guidelines |
| **AI Integration (`ai_service.py`)** | Implements AI client, prompt templates, calling | Defines context boundary & redaction validation |
| **Containerization & Docker** | Implements backend API Dockerfile | Implements dedicated scanner Dockerfiles & Compose security |
| **Database & API Routes** | Implements MongoDB models, routes, endpoints | Consumes finding contracts |
| **Security Testing** | Implements API unit & route tests | Implements fixtures, false-positive & container security tests |

---

## 10. Cross-Developer Dependencies, Alignment Status & Pending Questions

To prevent assumptions, breaking interface shifts, and ownership conflicts across workstreams, all shared touchpoints between Dev A, Dev B, and Dev C are tracked with explicit alignment statuses:

### 10.1 Shared Interface Matrix

| Shared Interface | Components Involved | Owners / Stakeholders | Current Status | Alignment Details / Invariant |
|---|---|---|:---:|---|
| **Finding Schema Contract** | `backend/app/schemas/finding.py`<br>`frontend/src/components/findings/*` | Dev B (Schema Owner)<br>Dev C (Producer)<br>Dev A (Consumer) | **AGREED** (Existing)<br>*(Refinements: **PENDING**)* | Dev C strictly conforms to Dev B's current `Finding` model without modifying it. Proposed type tightenings (`Literal` confidence/domain) are marked PENDING Dev B approval. |
| **Domain Taxonomy & Naming** | `specs/CYBERSECURITY_DOMAINS_SPEC.md`<br>`frontend/src/components/findings/DomainFilter.jsx`<br>`backend/app/api/routes/findings.py` | Dev C (Taxonomy Owner)<br>Dev A (Filter UI)<br>Dev B (Query Parameter) | **PENDING DEV A / DEV B AGREEMENT** | The 5 canonical domain display strings are specified. Exact query param format (full string vs. snake_case slug) must be agreed with Dev B and Dev A. |
| **Scan Status Nomenclature** | `backend/app/schemas/scan.py`<br>`frontend/src/components/common/ScanProgress.jsx`<br>`backend/app/scanners/base_scanner.py` | Dev B (Scan API Owner)<br>Dev A (UI Progress)<br>Dev C (Scanner Module) | **AGREED (Separated)** | Public scan job status (`pending`, `processing`, `completed`, `failed`) is owned by Dev B. Internal tool execution status (`ScannerStatus`) is private between Dev C and Dev B's orchestrator. |
| **Archive Ingestion & Security** | `backend/app/services/extraction_service.py`<br>`backend/app/utils/file_utils.py`<br>`specs/ZIP_ARCHIVE_SECURITY_SPEC.md` | Dev B (Implementation Owner)<br>Dev C (Security Reqs / Tests) | **PENDING DEV B IMPLEMENTATION** | Dev C specified security invariants (100MB, 5000 files, 250MB, 100:1 ratio, commonpath check, symlink drop). Dev B owns implementation without Dev C modifying existing code. |
| **Scanner Container Execution Architecture** | `docker-compose.yml`<br>`backend/Dockerfile`<br>`specs/SECURE_SCAN_EXECUTION_SPEC.md` | Dev C (DevOps / Container Security)<br>Dev B (Backend Deployment) | **PENDING ARCHITECTURAL DECISION** | Deciding between dedicated ephemeral scanner containers spawned via Docker socket vs. a dedicated scanner sidecar service vs. multi-stage binary bundling for Phase 4. |
| **AI Sanitization Context Interface** | `backend/app/ai/ai_service.py`<br>`backend/app/ai/prompts.py` | Dev B (AI Service Owner)<br>Dev C (Security / Redaction Spec) | **AGREED IN PRINCIPLE**<br>*(Implementation: **PENDING**)* | Dev C specified that only sanitized finding objects (never source trees or unredacted keys) pass to AI. Dev B implements the client and prompts in Phase 2. |

---

## 11. Specific Alignment Questions for Teammates

### Questions for Dev B (Backend Developer):
1. **Finding Schema Refinements:**
   - Do you agree with upgrading `confidence: str` to `confidence: Literal["high", "medium", "low"] = "medium"` and typing `domain` to the 5 canonical domain strings in `backend/app/schemas/finding.py` during Phase 3, or should Dev C continue using string types indefinitely?
2. **Scanner Execution Return Envelope:**
   - Would you prefer `BaseScanner.scan(workspace)` to return a typed `ScannerExecutionResult` object (containing findings, tool execution status, duration, and captured error message), or a bare `list[dict]` leaving orchestration status tracking to `scan_service.py`?
3. **Scanner Packaging & Invocation in Docker:**
   - In `docker-compose.yml`, would you prefer Dev C to introduce a dedicated `scanner` container service communicating via asynchronous job queues / shared volumes, or should scanner CLI binaries (Semgrep, Bandit, Gitleaks, OSV-Scanner) be packaged into a specialized scanner worker container?
4. **Archive Security Invariants:**
   - Are the proposed archive limits (`MAX_UPLOAD_SIZE = 100MB`, `MAX_ARCHIVE_ENTRIES = 5000`, `MAX_UNCOMPRESSED_SIZE = 250MB`, `MAX_COMPRESSION_RATIO = 100:1`) acceptable for the backend storage environment, or should they be adjusted?

### Questions for Dev A (Frontend Developer):
1. **Domain Filter Values in UI:**
   - For `DomainFilter.jsx` and API requests to `/api/scans/{scanId}/findings?domain=...`, does the frontend prefer using full display titles (e.g. `"Web Application Security"`) or URL-safe slug identifiers (e.g. `"web_security"`)?
2. **Null Line Number Display:**
   - In `VulnerabilityCard.jsx` and `FindingDetails.jsx`, does the UI already support findings with `line: null` (manifest-wide and file-wide vulnerabilities) by rendering "File-level" or "Manifest-level", or is a numeric fallback expected?
3. **Severity & Confidence Badges:**
   - Does `SeveritySummary.jsx` require confidence counts in addition to severity counts (`critical`, `high`, `medium`, `low`)?

