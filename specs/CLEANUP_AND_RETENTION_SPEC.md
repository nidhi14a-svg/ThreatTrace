# Cleanup and Retention Specification

- **Document:** `specs/CLEANUP_AND_RETENTION_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator / Implementation Owner:** Dev B (Backend Developer)
- **Status:** Approved Specification (Phase 4, Task 4.7)
- **Version:** 1.0.0

---

## 1. Retention Lifecycle Policies

To prevent disk saturation and ensure privacy compliance, temporary files follow strict retention boundaries:

| Asset Type | Location | Max Retention Duration (TTL) | Deletion Trigger | Responsible Component |
|---|---|---|---|---|
| **Uploaded ZIP Archives** | `/tmp/thread-trace/uploads/*.zip` | 15 minutes (or immediately after extraction) | Post-extraction or TTL sweep | `extraction_service.py` / `cleanup_workspaces.py` |
| **Extracted Workspaces** | `/tmp/thread-trace/workspaces/<uuid>/` | 30 minutes | `finally:` block after scan completion or TTL sweep | Backend Orchestrator / `cleanup_workspaces.py` |
| **Scanner Worker Output** | `/tmp/thread-trace/workspaces/<uuid>/output/` | 30 minutes | Deleted with workspace directory | Backend Orchestrator / `cleanup_workspaces.py` |
| **MongoDB Scan Reports** | MongoDB collection `scans` | 30 days | MongoDB TTL index on `created_at` field | MongoDB Engine (Dev B) |
| **Scanner Worker Containers** | Docker host | Lifetime of task (or persistent worker) | `docker compose down -v` | DevOps / Makefile |

---

## 2. Immediate Cleanup Invariant

All temporary workspaces must be cleaned up in a mandatory Python `finally:` block:

```python
try:
    # 1. Extract archive
    # 2. Run scanners
    # 3. Read and normalize findings
finally:
    # Always wipe extracted source code and output
    workspace_manager.cleanup_workspace(workspace_id)
```

---

## 3. Orphan Sweeper Script: `scripts/cleanup_workspaces.py`

If the backend process crashes or is killed via `SIGKILL`, the `finally:` block will not execute. To handle orphaned directories, a dedicated Python utility `scripts/cleanup_workspaces.py` is provided.

### Features:
- Sweeps `/tmp/thread-trace/workspaces` and `/tmp/thread-trace/uploads`.
- Compares directory modification time against configurable `--ttl-seconds` (default: 1800s / 30m).
- Supports `--dry-run` to preview directories to be deleted without removing them.
- Prevents path traversal outside configured base directories.
- Skips active locks or non-directory files safely.
