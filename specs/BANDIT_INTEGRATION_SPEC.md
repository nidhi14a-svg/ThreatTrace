# Bandit Integration Specification

- **Document:** `specs/BANDIT_INTEGRATION_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator:** Dev B (Backend Developer)
- **Implementation File:** `backend/app/scanners/bandit_scanner.py`
- **Task Reference:** Phase 2, Task 2.3 — Bandit Integration
- **Status:** Approved Specification & Implementation
- **Version:** 1.0.0

---

## 1. Executive Summary & Purpose

Bandit is a dedicated security linter developed by the PyCQA community designed specifically for Python source code. It parses Python Abstract Syntax Trees (AST) and evaluates them against a suite of security plugins.

In Thread Trace, Bandit complements Semgrep by providing deep Python-specific checks for:
- **Web Application Security:** SQL injection via formatted strings (`B608`), shell injection via `subprocess` or `os.system` (`B602`, `B605`), and insecure deserialization (`B301: pickle`).
- **Network & Communication Security:** Disabled certificate verification (`B501: requests_no_cert_validation`), insecure SSL versions (`B502`), and bad SSL defaults (`B503`).
- **Authentication & Access Control:** Weak cryptographic hashing (`B303: md5`, `B324: hashlib_new_insecure`), hardcoded passwords (`B105`, `B106`), and weak pseudo-random generators (`B311: random`).
- **Dependency & Configuration Security:** Dangerous temp file creation (`B306: mktemp_q`) and world-writable file permissions (`B103: chmod`).

Task 2.3 implements `BanditScanner` adhering to the `BaseScanner` interface. It executes Bandit as an unprivileged subprocess, checks for the presence of Python source files, captures JSON output, normalizes paths to relative coordinates, handles Bandit's unique exit code conventions (exit code 1 on findings), and contains failures safely.

---

## 2. CLI Execution & Invocation Parameters

Bandit is invoked via asynchronous subprocess execution (`asyncio.create_subprocess_exec`). Subprocess arguments are passed strictly as a validated list; `shell=True` is prohibited.

### 2.1 Default Command Structure
```bash
bandit -r <workspace_path> -f json -q -x .venv,venv,env,node_modules,tests,__pycache__,.pytest_cache
```

### 2.2 Parameter Definitions
- **`-r`:** Recursively analyzes Python source files within the workspace.
- **`-f json`:** Mandates JSON-formatted output to stdout for programmatic parsing.
- **`-q` / `--quiet`:** Suppresses informational banners and progress output.
- **`-x <paths>`:** Comma-separated list of directories to exclude from analysis (e.g. virtual environments, node modules, tests).
- **`-c <config_file>`:** (Optional) Path to a custom Bandit YAML configuration file specifying enabled/disabled test IDs.
- **`<workspace_path>`:** Target workspace directory (resolved canonical path).

---

## 3. Python-Specific Language Boundaries & Pre-Execution Checks

Bandit is strictly capable of analyzing Python source code (`.py` files). Invoking Bandit on projects without Python source code produces empty reports or syntax errors.

### 3.1 Pre-Execution Workspace Verification
1. **Workspace Path Validation:**
   - Path must exist and be a directory.
   - If path does not exist: returns `status="skipped"`, `findings=[]`, `error=None`.
   - If path is not a directory or is empty: returns `status="failed"`.
2. **Python File Existence Check:**
   - The scanner inspects the workspace for the presence of any `.py` file (excluding virtual environments and caches).
   - If **zero Python files exist** in the workspace:
     - Bandit execution is skipped.
     - Returns `status="skipped"`, `findings=[]`, `error=None`.
     - *Rationale:* Satisfies the project specification that unavailable or unsupported workspaces report `skipped` without raising spurious scanner errors.

---

## 4. Subprocess Safety & Resource Bounding

1. **Subprocess Isolation:**
   - Executed with `cwd=str(resolved_workspace)`.
   - Command arguments are passed as a discrete list of strings (`shell=False`).
2. **Timeout Enforcement:**
   - Defaults to `60.0` seconds (configurable via constructor or `BANDIT_TIMEOUT_SECONDS`).
   - If execution exceeds this threshold: process is killed via `process.kill()` and returns `status="failed"`.
3. **Memory Bounding:**
   - Buffer limit defaults to `10 MB` (`10 * 1024 * 1024` bytes).
   - If stdout exceeds this limit, execution is aborted with an error rather than exhausting host RAM.
4. **Safe Error Sanitization:**
   - Stderr is stripped of ANSI escape sequences and truncated to at most 500 characters.
   - Code snippets, credentials, and full tracebacks are never exposed in error attributes.

---

## 5. Raw Finding Data Contract

In accordance with Phase 2 architecture, `BanditScanner` emits **raw finding dictionaries** directly into `ScannerExecutionResult.findings`. Dev B's backend orchestrator owns subsequent normalization into the shared `Finding` model.

### 5.1 Raw Finding Dictionary Schema
```python
{
    "scanner_name": "bandit",
    "rule_id": "bandit.B501",                  # str: prefixed Bandit test ID (e.g. bandit.B501)
    "severity": "HIGH",                        # str: original Bandit severity (HIGH, MEDIUM, LOW)
    "confidence": "HIGH",                      # str: original Bandit confidence (HIGH, MEDIUM, LOW)
    "raw_category": "request_with_no_cert_validation", # str | None: Bandit test_name or CWE
    "file": "app/services/client.py",          # str: strictly relative POSIX path within workspace
    "line": 42,                                # int | None: 1-indexed line number
    "line_range": [42],                        # list[int]: affected line numbers
    "message": "Certificate verification disabled", # str: issue_text from Bandit
    "evidence": "verify=False",                # str: code snippet (bounded to 1000 chars)
    "metadata": {                              # dict: raw metadata preserved for backend
        "test_id": "B501",
        "test_name": "request_with_no_cert_validation",
        "cwe": {"id": 295, "link": "..."},
        "more_info": "https://bandit.readthedocs.io/..."
    }
}
```

### 5.2 Path Security Invariant
All finding paths in Bandit's output (`filename`) are validated against the canonical workspace root using `Path.resolve()`:
```python
resolved_path = (workspace_root / raw_filename).resolve()
relative_path = resolved_path.relative_to(workspace_root).as_posix()
```
If a path escapes the workspace root (e.g. through directory traversal or symlink escape), it is securely replaced with `"[REJECTED_OUTSIDE_WORKSPACE]"`, preventing disclosure of host files.

---

## 6. Bandit Exit Codes & Execution Status Matrix

Bandit utilizes non-standard exit code conventions:
- **`0`:** Scan completed successfully with **0 issues found**.
- **`1`:** Scan completed successfully with **issues found** (findings present).
- **`2`:** Fatal execution / configuration error.

`BanditScanner` interprets exit codes 0 and 1 with valid JSON as successful/partial scans:

| Subprocess Outcome | Output Valid? | Status | Findings State | Error Field |
|---|---|---|---|---|
| Exit code 0 or 1, no errors in JSON | Valid JSON | `success` | Parsed list of raw findings (>= 0) | `None` |
| Exit code 0 or 1, file errors in JSON | Valid JSON with `errors` | `partial` | Usable findings parsed from `results` | Summarized file error warning |
| Exit code >= 2, no usable output | No / Invalid JSON | `failed` | `[]` | Sanitized stderr summary |
| Missing binary (`FileNotFoundError`) | N/A | `failed` (or `skipped` if configured) | `[]` | `"Bandit executable not found: 'bandit'"` |
| Subprocess timeout (`TimeoutError`) | N/A | `failed` | `[]` | `"Bandit execution timed out after 60.0 seconds"` |
| Workspace missing or non-directory | N/A | `skipped` (missing) / `failed` (file) | `[]` | Clean diagnostic message |
| Workspace contains 0 Python files | N/A | `skipped` | `[]` | `None` |

---

## 7. Backward Compatibility & Interface Compliance

- `BanditScanner` inherits from `BaseScanner` and implements `name = "bandit"` and `async def scan(workspace: str) -> ScannerExecutionResult`.
- Zero changes are made to Dev B's schemas, database models, or FastAPI routers.
- The scanner operates fully self-contained and mock-testable without requiring a real Bandit binary in test environments.
