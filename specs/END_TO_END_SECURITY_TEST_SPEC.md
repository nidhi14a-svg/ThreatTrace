# End-to-End Security Testing Specification

**File:** `specs/END_TO_END_SECURITY_TEST_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Collaborator:** Dev B — Upload, Extraction, Orchestration & Reporting  
**Implementation Targets:** `backend/tests/test_end_to_end_security.py`, `backend/app/scanners/workspace.py`, `backend/app/scanners/worker_runner.py`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 6, Task 6.4)  
**Status:** APPROVED & IMPLEMENTED  

---

## 1. Overview & Objectives

This specification defines the comprehensive validation of the complete Thread Trace scan lifecycle, from the arrival of an untrusted ZIP archive through archive validation, isolated extraction, static analysis execution, finding normalization, secret redaction, aggregation, report generation, and ephemeral workspace cleanup.

### Invariant:
Uploaded code is **never executed**. No build scripts, setup hooks, or application packages are imported or invoked during scanning.

---

## 2. Complete End-to-End Workflow Stages

The 11 distinct stages of the Thread Trace scan workflow:

```
[1. Upload ZIP Bytes]
        │
        ▼
[2. Archive Security Validation] ──(Violation)──> [Reject with 400 / Log Audit]
        │
        ▼ (Valid)
[3. Workspace Creation] (WorkspaceManager: /tmp/thread-trace/workspaces/<scan_id>/)
        │
        ▼
[4. Secure Extraction] (Into <workspace>/source/ with path traversal guards)
        │
        ▼
[5. Scanner Invocation] (Worker process / container with read-only source mount)
        │
        ▼
[6. Static Scanner Execution] (Semgrep, Bandit, Secrets, OSV, Custom AST Rules)
        │
        ▼
[7. Finding Normalization] (Pydantic Finding schema enforcement)
        │
        ▼
[8. In-Memory Secret Redaction] (Redact tokens, passwords, multiline keys)
        │
        ▼
[9. Finding Aggregation & Deduplication] (Tool priority + status aggregation)
        │
        ▼
[10. Report Payload Generation] (Structured metrics, severity & domain summaries)
        │
        ▼
[11. Ephemeral Workspace Cleanup] (shutil.rmtree workspace, verify zero leakage)
```

---

## 3. Test Cases & Verification Scenarios

The automated test suite in `backend/tests/test_end_to_end_security.py` verifies:

| Scenario | Input Payload | Expected Workflow Behavior | Verification Check |
|---|---|---|---|
| **E2E-01: Successful Scan** | Valid ZIP of synthetic project | Passes archive validation, extracts, runs scanners, normalizes, generates report, cleans workspace. | Status: `success`, findings > 0, workspace deleted after scan. |
| **E2E-02: Partial Scanner Failure** | Valid ZIP, one scanner fails | Scanner fault isolated; other scanners complete; aggregate status becomes `partial`. | Status: `partial`, failed scanner logged, remaining findings preserved. |
| **E2E-03: Invalid ZIP Upload** | Corrupted / non-ZIP bytes | Rejection at stage 2; no extraction performed; no workspace created. | `ZipSecurityValidationError` raised; zero disk writes. |
| **E2E-04: Archive Security Rejection (Zip Slip)** | ZIP containing `../../evil.sh` | Detected and rejected immediately before extraction; workspace cleaned up. | `ZipSecurityValidationError` ("Path traversal detected"); no files written outside workspace. |
| **E2E-05: Archive Security Rejection (Zip Bomb)** | 1 KB ZIP decompressing to >2 MB (>100:1 ratio) | Rejected at validation stage. | `ZipSecurityValidationError` ("Compression ratio exceeds limit"). |
| **E2E-06: Synthetic Secrets Scan** | Project containing synthetic AWS & GitHub tokens | Secrets detected, normalized, and redacted in evidence before report generation. | Evidence contains `[REDACTED_AWS_KEY]`, no cleartext secrets in report. |
| **E2E-07: Clean Repository Scan** | Project with clean, secure code | Scanners execute with zero errors; no false positives emitted. | Status: `success`, `total_findings: 0`. |
| **E2E-08: Workspace Cleanup On Failure** | Scan that aborts due to invalid workspace | Workspace directory removed regardless of execution outcome. | `workspace_dir.exists() == False`. |

---

## 4. Execution Environment Note

- In environments with an active Docker daemon, the worker executes in the dedicated unprivileged container (`Dockerfile.scanner`).
- In environments without an active Docker daemon (e.g. local dev Windows host without Docker Desktop), the test harness exercises the worker runner directly in-process via `worker_runner.run_scanners()` and `WorkspaceManager`.
- This specification explicitly distinguishes between in-process integration testing and live container runtime testing.
