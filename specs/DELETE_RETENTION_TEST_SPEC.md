# Delete and Retention Verification Specification

**File:** `specs/DELETE_RETENTION_TEST_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Collaborator:** Dev B — API Routes, Database Models & Scan Lifecycle  
**Implementation Targets:** `backend/app/scanners/workspace.py`, `scripts/cleanup_workspaces.py`, `backend/tests/test_delete_retention.py`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 6, Task 6.5)  
**Status:** APPROVED & IMPLEMENTED  

---

## 1. Overview & Objectives

Thread Trace ingests untrusted source code and generates sensitive security findings. A failure to safely and reliably purge ephemeral scan data exposes the platform to:
1. **Source Code Exposure:** Customer or proprietary source code lingering on the filesystem beyond the scan window.
2. **Disk Exhaustion (DoS):** Accumulation of large extracted workspaces and raw JSON artifacts filling host disk volumes.
3. **Information Leakage:** Scanner output and evidence files accessible across scan boundaries.

This specification defines the **data lifecycle, deletion protocols, retention boundaries, and automated cleanup mechanisms**.

---

## 2. Retention Boundaries (Dev B vs. Dev C)

To ensure privacy and maintain auditability:

| Artifact Type | Retention Period | Deletion Mechanism | Owner |
|---|---|---|---|
| **Raw Upload Archives (ZIP)** | Ephemeral (Deleted immediately after extraction validation) | `upload_service.py` / File unlinking | Dev B |
| **Extracted Source Code (`/source/`)** | Ephemeral (Deleted immediately upon scan completion or failure) | `WorkspaceManager.cleanup_workspace()` | Dev C / Dev B |
| **Scanner Output Artifacts (`/output/`)** | Ephemeral (Deleted immediately after JSON ingestion into DB) | `WorkspaceManager.cleanup_workspace()` | Dev C / Dev B |
| **Abandoned / Interrupted Workspaces** | TTL = 1,800 seconds (30 minutes) | Background sweeper `scripts/cleanup_workspaces.py` | Dev C |
| **Persistent Findings & Scan Metadata** | Business Retention Policy (e.g. 90 days in MongoDB) | API Route `DELETE /api/scans/{scan_id}` | Dev B |
| **Audit Logs** | Long-term immutable audit log | Structured log shipping | Dev B |

---

## 3. Deletion Implementation Requirements

### 3.1 Workspace Removal (`WorkspaceManager.cleanup_workspace`)
- Resolves workspace path and verifies `is_relative_to(base_dir)` to guarantee no path breakout.
- Deletes both `source/` and `output/` subdirectories recursively using `shutil.rmtree()`.
- **Idempotence:** Calling `cleanup_workspace()` on an already-deleted or non-existent workspace ID returns `False` safely without raising unhandled exceptions.

### 3.2 Time-to-Live (TTL) Sweeper (`scripts/cleanup_workspaces.py`)
- Background cron or container maintenance process sweeps `WORKSPACE_BASE_DIR`.
- Calculates directory age using `mtime`. If age > `ttl_seconds` (default: 1,800s), directory is purged.
- Supports `--dry-run` flag for auditability.
- Logs total bytes freed and records any directory-level errors.

### 3.3 Path Traversal Prevention
- `validate_workspace_id()` rejects any workspace ID containing `..`, `/`, `\`, null bytes, or non-alphanumeric characters.
- Base directory breakout detection prevents symbolic link redirection.

---

## 4. Verification Scenarios (`test_delete_retention.py`)

1. **Immediate Workspace Deletion:** Verify `cleanup_workspace()` completely purges the entire workspace directory including `source/` and `output/`.
2. **Idempotent Deletion:** Verify repeated deletion calls on the same workspace ID succeed safely.
3. **TTL Expiration Sweeping:** Create mock workspaces with simulated past timestamps; verify that only expired workspaces are removed while active workspaces remain intact.
4. **Dry Run Mode:** Verify `--dry-run` reports bytes to be freed without deleting filesystem entries.
5. **Path Traversal Protection:** Verify attempts to pass `../../etc` to cleanup raise `WorkspaceSecurityError`.
6. **Failed Scan Cleanup:** Verify that unhandled exceptions during scan execution trigger workspace cleanup in `finally` blocks.
