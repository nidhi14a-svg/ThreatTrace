# Scanner Failure Specification: Partial Success, Fault Isolation & Error Semantics

**File:** `specs/SCANNER_FAILURE_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Targets:** `backend/app/scanners/base_scanner.py`, `backend/app/scanners/`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 2, Task 2.7)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

This specification defines the **Fault Isolation Architecture**, **Scanner Failure Semantics**, and **Status Aggregation Rules** for Thread Trace.

In a multi-scanner architecture where different tools (Semgrep, Bandit, Gitleaks, OSV-Scanner, and custom rules) analyze the same uploaded workspace concurrently, scanner executions are subject to varied runtime conditions:
- Unsupported programming languages or missing lockfiles.
- CLI process timeouts and resource exhaustion.
- Process crashes, syntax parse errors on unparseable target files, or missing tool binaries.
- Partial findings alongside file-level errors.

### Core Architectural Mandate: Zero Cascading Failure
A failure, crash, timeout, or missing executable in **any individual scanner must never abort the overall scan orchestration** or corrupt/drop valid findings returned by other scanners. Every scanner executes as an isolated unit whose outcome is represented in a dedicated `ScannerExecutionResult`.

---

## 2. Standardized Scanner Status Taxonomy

Every scanner execution must conclude in exactly one of four mutually exclusive statuses:

```
                                  [ Scanner Invocation ]
                                            |
                   +------------------------+-----------------------+
                   |                                                |
          (Pre-scan Checks)                                 (Process Execution)
                   |                                                |
         +---------+---------+                            +---------+---------+
         |                   |                            |                   |
    [Workspace          [Workspace                   [Exit Code 0/1      [Crash, Timeout,
   Unsupported /       Valid & Files                 + Clean Output]     Exit >= 2, No JSON]
   No Manifests]         Present]                         |                   |
         |                   |                            v                   v
         v                   v                        (SUCCESS)            (FAILED)
     (SKIPPED)        (Run Subprocess)                    |
                             |                    (Warnings / Syntax
                             v                    Errors on Some Files)
                      [Exit Code 0/1                      |
                     + Some Warnings]                     v
                             |                        (PARTIAL)
                             +----------------------------+
```

### 2.1 `success`
- **Definition:** The scanner executed to completion without fatal errors or file-level syntax errors.
- **Findings:** List of zero or more normalized raw finding dictionaries (`findings: list[dict]`).
- **Error:** Strictly `error: None`.
- **Duration:** Monotonically measured execution duration (`duration_seconds > 0.0`).

### 2.2 `partial`
- **Definition:** The scanner completed execution and extracted valid findings, but encountered non-fatal anomalies, such as:
  - File-level syntax errors on certain files (e.g., Bandit or Semgrep encountering an unparseable source file while analyzing others).
  - CLI non-zero exit codes that still emitted valid findings.
  - Informational warning banners or non-fatal output truncations.
- **Findings:** Non-empty list of valid findings extracted from successfully analyzed files.
- **Error:** Sanitized, bounded description of the partial errors or warnings (`error: str`, max 1,000 characters).

### 2.3 `failed`
- **Definition:** The scanner failed to execute or produce valid findings due to:
  - Subprocess hard timeout (`timeout_seconds` exceeded).
  - Missing executable binary on `PATH` (when skip-on-missing is disabled).
  - Subprocess crash (SIGSEGV, non-zero exit code without JSON output).
  - Malformed or corrupted JSON output that cannot be recovered.
  - Invalid workspace path (empty string or file instead of directory).
- **Findings:** Strictly empty list (`findings: []`).
- **Error:** Safe, bounded diagnostic description (`error: str`, max 1,000 characters).

### 2.4 `skipped`
- **Definition:** The scanner was intentionally not executed because:
  - The workspace does not contain compatible targets (e.g., Bandit skipped when 0 `.py` files exist; OSV-Scanner skipped when 0 dependency manifests exist).
  - The workspace directory is empty or does not exist.
  - The scanner binary is absent and `allow_skip_if_missing=True` is configured.
- **Findings:** Strictly empty list (`findings: []`).
- **Error:** Strictly `error: None`. (A skip is an expected operational branch, not a diagnostic failure).

---

## 3. Failure Semantics by Scanner

| Scanner | Skipped Condition | Partial Condition | Failed Condition |
|---|---|---|---|
| **Semgrep** | Workspace empty or non-existent. | Non-zero exit with JSON findings; or `errors` array in Semgrep JSON while `results` contains findings. | Subprocess timeout; exit code >= 2 without JSON; unparseable JSON; missing `semgrep` binary. |
| **Bandit** | Workspace contains zero `.py` files; empty workspace. | Non-zero exit code 1 with findings; or `errors` array in Bandit JSON while `results` contains findings. | Subprocess timeout; exit code >= 2 without findings; malformed JSON; missing `bandit` binary. |
| **Gitleaks** | Workspace empty or non-existent. | Non-zero exit code >= 2 while temp report JSON contains valid findings. | Subprocess timeout; exit code >= 2 without report; unparseable report JSON; missing `gitleaks` binary. |
| **OSV-Scanner** | Workspace contains zero supported manifests/lockfiles; empty workspace. | Non-zero exit code with warnings while findings are successfully parsed. | Subprocess timeout; exit code >= 2 without JSON; unparseable JSON; missing `osv-scanner` binary. |
| **Custom Rules** | Workspace empty or non-existent. | Execution completes with rule evaluation warnings on specific files. | Syntax error in custom rule definition; unhandled rule exception. |

---

## 4. Fault Isolation & Concurrency Architecture

### 4.1 Non-Cascading Execution Model
Scanners are executed concurrently by Dev B's orchestration service (`backend/app/services/scan_service.py`):
```python
# Orchestrator Concurrency Pattern (Guaranteed Non-Blocking)
tasks = [
    semgrep_scanner.scan(workspace),
    bandit_scanner.scan(workspace),
    secrets_scanner.scan(workspace),
    dependency_scanner.scan(workspace),
]

# return_exceptions=True guarantees that an unhandled exception in one task
# does not terminate or cancel concurrent tasks.
results = await asyncio.gather(*tasks, return_exceptions=True)
```

### 4.2 Safe Execution Wrapper (`safe_scan`)
To ensure that an unhandled Python exception within a scanner adapter can never leak to the orchestrator or cancel concurrent tasks, `BaseScanner` provides the `safe_scan(workspace: str)` method:
```python
async def safe_scan(self, workspace: str) -> ScannerExecutionResult:
    try:
        return await self.scan(workspace)
    except Exception as exc:
        return self.create_result(
            status="failed",
            findings=[],
            duration_seconds=0.0,
            error=self.bound_error(f"Unexpected scanner exception in {self.name}: {exc}"),
        )
```

---

## 5. Status Aggregation Rules for Dev B Orchestrator

When aggregating individual scanner results into the overall job status for the scan report, Dev B's backend must apply the following deterministic state transition matrix:

```
+--------------------------------------------------------------------------------+
|                             Scanner Results Set                                |
+--------------------------------------------------------------------------------+
                                        |
      +---------------------------------+--------------------------------+
      |                                 |                                |
[All Statuses == 'skipped']    [All Statuses == 'failed']      [At least one 'success']
      |                                 |                                |
      v                                 v                                v
 Overall: SKIPPED               Overall: FAILED            [Check Remaining Scanners]
 (Findings: 0)                   (Findings: 0)                           |
                                                 +-----------------------+-----------------------+
                                                 |                                               |
                                        [All Others are                         [At least one scanner
                                      'success' or 'skipped']                     'failed' or 'partial']
                                                 |                                               |
                                                 v                                               v
                                          Overall: SUCCESS                       Overall: PARTIAL_SUCCESS
                                        (All Findings Kept)                         (All Valid Findings
                                                                                    Preserved & Reported)
```

### 5.1 Aggregation Matrix Table
| Individual Scanner States | Overall Job Status | Findings Behavior | Reporting Action |
|---|---|---|---|
| All `success` | `success` | Complete findings aggregated | Normal report generated. |
| Mixed `success` + `skipped` | `success` | Findings from executed tools | Clean report; note skipped tools in metadata. |
| Mixed `success` + `failed` | `partial` | **Preserve all findings from successful scanners** | Report generated with warning banners for failed tools. |
| Mixed `partial` + `success` | `partial` | All valid findings preserved | Report generated with warning notes. |
| All `failed` | `failed` | Zero findings | Failure report explaining tool crashes / timeouts. |
| All `skipped` | `skipped` | Zero findings | Informational report: no supported files uploaded. |

---

## 6. Error Sanitization & Diagnostic Bounding

### 6.1 Diagnostic Safety Rules
1. **No Source Exposure:** Stderr and exception messages must never include raw source code lines or snippets.
2. **No Credential Exposure:** Error messages must not output environment variables, API tokens, or authorization headers.
3. **Length Bounding:** All error descriptions assigned to `ScannerExecutionResult.error` must be capped at 1,000 characters.
4. **Host Path Redaction:** Absolute host paths (outside the workspace) must not be revealed in client-facing error strings.

---

## 7. Cross-Developer Responsibilities (Dev B Alignment)

1. **Dev C (Scanners):**
   - Implements `safe_scan()` and `scan()` returning valid `ScannerExecutionResult`.
   - Never raises unhandled exceptions out of `safe_scan()`.
   - Populates `ScannerExecutionResult.status` strictly with `"success"`, `"partial"`, `"failed"`, or `"skipped"`.
   - Never attempts to directly update the MongoDB `ScanJob` model or FastAPI responses.
2. **Dev B (Orchestration & Reporting):**
   - Invokes scanners via `safe_scan()`.
   - Normalizes raw finding dictionaries into canonical `Finding` models.
   - Computes overall job status using the Aggregation Matrix defined in Section 5.1.
   - Stores individual scanner statuses in MongoDB for frontend display.
