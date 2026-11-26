# Semgrep Integration Specification

- **Document:** `specs/SEMGREP_INTEGRATION_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator:** Dev B (Backend Developer)
- **Implementation File:** `backend/app/scanners/semgrep_scanner.py`
- **Task Reference:** Phase 2, Task 2.2 — Semgrep Integration
- **Status:** Approved Specification & Implementation
- **Version:** 1.0.0

---

## 1. Executive Summary & Purpose

Semgrep is the primary multi-language semantic AST pattern matching engine in Thread Trace. It provides static analysis for:
- **Web Application Security:** OWASP Top 10 vulnerabilities (SQLi, XSS, SSRF, Command Injection, Path Traversal).
- **Authentication & Access Control:** Broken auth, missing authorization decorators, JWT misconfigurations.
- **Network & Communication Security:** Insecure protocols and certificate verification issues.
- **Dependency & Configuration Security:** Framework initialization and configuration flaws.

Task 2.2 implements the `SemgrepScanner` adapter adhering strictly to the `BaseScanner` interface. The adapter executes Semgrep as an unprivileged subprocess, captures structured JSON output, bounds memory consumption, normalizes paths to relative workspace boundaries, and handles partial execution and failure conditions gracefully without crashing the overall scanning pipeline.

---

## 2. CLI Execution & Invocation Parameters

Semgrep is invoked via asynchronous subprocess execution (`asyncio.create_subprocess_exec`). Subprocess arguments are passed strictly as a validated list; `shell=True` is strictly prohibited.

### 2.1 Default Command Structure
```bash
semgrep scan \
  --json \
  --config p/owasp-top-ten \
  --metrics=off \
  --disable-version-check \
  --max-target-bytes 1000000 \
  --timeout 10 \
  <workspace_path>
```

### 2.2 Parameter Definitions
- **`scan`:** Modern Semgrep CLI subcommand for target analysis.
- **`--json`:** Mandates JSON-formatted output to stdout for programmatic parsing.
- **`--config <rules>`:** Specifies rule pack. Defaults to `p/owasp-top-ten` (customizable via constructor or `SEMGREP_RULES`).
- **`--metrics=off`:** Disables telemetry reporting to external Semgrep metrics servers (maintains air-gap privacy).
- **`--disable-version-check`:** Prevents outbound network calls to check for software updates.
- **`--max-target-bytes 1000000`:** Enforces a 1 MB per-file size ceiling to prevent parser denial of service.
- **`--timeout 10`:** Sets a 10-second per-file evaluation timeout inside Semgrep.
- **`<workspace_path>`:** Target workspace directory (resolved canonical path).

---

## 3. Subprocess Safety & Resource Bounding

1. **Working Directory & Path Bounding:**
   - The subprocess executes with `cwd=str(resolved_workspace)`.
   - The target path is verified to exist and be a directory before invocation.
2. **Timeout Enforcement:**
   - Scanner-level timeout defaults to `60.0` seconds (configurable).
   - If Semgrep does not complete within `timeout_seconds`, the process is terminated via `process.kill()`, awaited, and returns `status="failed"`.
3. **Memory Bounding:**
   - Output buffer is capped at `10 MB` (`10 * 1024 * 1024` bytes).
   - If stdout exceeds this limit, execution is aborted with an error rather than exhausting backend RAM.
4. **Safe Error Sanitization:**
   - Raw stderr output is stripped of ANSI escape sequences and bounded to a maximum of 500 characters.
   - Secrets, full file contents, and environment variables are never exposed in error messages.

---

## 4. Raw Finding Data Contract

In accordance with Phase 2 architecture, `SemgrepScanner` emits **raw finding dictionaries** directly into `ScannerExecutionResult.findings`. Dev B's backend orchestrator owns subsequent normalization into the shared Pydantic `Finding` model.

### 4.1 Raw Finding Dictionary Schema
```python
{
    "scanner_name": "semgrep",
    "rule_id": check_id,             # str: e.g. "python.lang.security.injection.sql.sql-injection"
    "severity": severity,             # str: Semgrep severity ("ERROR", "WARNING", "INFO")
    "raw_category": raw_category,     # str | None: from metadata.category or subcategory
    "file": relative_path,            # str: relative POSIX path within workspace
    "line": start_line,               # int | None: 1-indexed line number
    "col": start_col,                 # int | None: 1-indexed column number
    "end_line": end_line,             # int | None: ending line number
    "end_col": end_col,               # int | None: ending column number
    "message": message,               # str: human-readable vulnerability description
    "evidence": evidence,             # str: bounded code snippet (max 1000 chars)
    "metadata": metadata,             # dict: raw metadata (cwe, owasp, confidence, etc.)
}
```

### 4.2 Path Security Invariant
All finding paths are verified against the canonical workspace root using `Path.resolve()`:
```python
resolved_path = (workspace_root / raw_path).resolve()
relative_path = resolved_path.relative_to(workspace_root).as_posix()
```
If a path escapes the workspace root (e.g., symlink traversal or malicious `../../`), it is rejected and replaced with `"[REJECTED_OUTSIDE_WORKSPACE]"`, preventing path disclosure of host files.

---

## 5. Execution Status Matrix

| Subprocess Outcome | Output Valid? | Status | Findings State | Error Field |
|---|---|---|---|---|
| Return code 0, no errors | Valid JSON | `success` | Parsed list of raw findings (>= 0) | `None` |
| Return code 0 or non-zero, recoverable file warnings | Valid JSON with `errors` | `partial` | Usable findings parsed from `results` | Summarized warning message |
| Non-zero exit, no usable output | No / Invalid JSON | `failed` | `[]` | Sanitized stderr summary |
| Missing binary (`FileNotFoundError`) | N/A | `failed` (or `skipped` if configured) | `[]` | `"Semgrep executable not found: 'semgrep'"` |
| Subprocess timeout (`TimeoutError`) | N/A | `failed` | `[]` | `"Semgrep execution timed out after 60.0 seconds"` |
| Workspace missing or invalid | N/A | `failed` | `[]` | `"Workspace path does not exist or is not a directory"` |
| Workspace empty (0 files) | N/A | `skipped` | `[]` | `None` |

---

## 6. Backward Compatibility & Interface Compliance

- `SemgrepScanner` inherits from `BaseScanner` and implements `name = "semgrep"` and `async def scan(workspace: str) -> ScannerExecutionResult`.
- Zero changes are made to Dev B's schemas, database models, or FastAPI routers.
- The scanner operates fully self-contained and mock-testable without requiring a real Semgrep binary in test environments.
