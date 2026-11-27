# Scanner Failure Test Specification

- **Document:** `specs/SCANNER_FAILURE_TEST_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target File:** `backend/tests/test_scanner_failures.py`
- **Status:** Approved Specification (Phase 5, Task 5.6)
- **Version:** 1.0.0

---

## 1. Objectives & Failure Modes

Verifies that any unexpected scanner engine crash, missing executable, subprocess timeout, or malformed stdout payload is contained safely without crashing the backend process or corrupting findings from remaining scanners.

### Failure Scenarios Tested:
1. **Missing Executable:** Binary not installed or missing from PATH returns `failed` (or `skipped` if skip policy enabled) with safe error message.
2. **Execution Timeout:** Subprocess exceeding hard timeout is terminated via `SIGKILL` and returns `failed` with diagnostic timeout message.
3. **Malformed JSON Output:** Non-JSON output, truncated JSON, or invalid root structures return `failed` without unhandled JSONDecodeError.
4. **Non-Zero Exit Code Handling:** Tool exit codes indicating unhandled parser errors return `partial` or `failed`.
5. **Resource Termination (OOM):** Subprocess killed by kernel signal returns `failed` without crashing parent process.
6. **Fault Isolation (`safe_scan`):** Individual scanner failure does not abort other concurrent scanner executions.
