# Scanner Container Architecture Specification

- **Document:** `specs/SCANNER_CONTAINER_ARCHITECTURE_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator / Implementation Owner:** Dev B (Backend Developer), Dev A (Frontend Developer)
- **Status:** Approved Specification (Phase 4, Task 4.1)
- **Version:** 1.0.0

---

## 1. Executive Summary & Core Architecture

Thread Trace executes automated static security analysis against untrusted source code repositories provided by external users. To defend against Remote Code Execution (RCE), Denial of Service (DoS), container breakout, and network pivoting, scanner execution must be quarantined in a **dedicated, restricted scanner worker container**.

### Critical Architecture Decision: Single Dedicated Scanner Worker

Rather than deploying five separate containers for each security tool (which would cause severe resource overhead, complex IPC coordination, and container lifecycle thrashing), Thread Trace deploys **exactly four service containers**:

```
+-----------------------------------------------------------------------------------------+
|                                    THREAD TRACE CLUSTER                                 |
|                                                                                         |
|  +------------------------+             +--------------------------------------------+  |
|  |       frontend         |             |                  backend                   |  |
|  | (Next.js / Port 3000)  | <---------> |            (FastAPI / Port 8000)           |  |
|  +------------------------+  [app-net]  +--------------------------------------------+  |
|                                            |                       |                    |
|                                  [db-net]  |          [scanner-net]|                    |
|                                            v                       v                    |
|                             +--------------------+   +-------------------------------+  |
|                             |      mongodb       |   |            scanner            |  |
|                             |  (Mongo 7 / 27017) |   |  (Dedicated Scanner Worker)   |  |
|                             |  *Internal Only*   |   |  *Air-gapped / Non-root*      |  |
|                             +--------------------+   +-------------------------------+  |
|                                                                     |                   |
|                                            +------------------------+                   |
|                                            | Mounts Ephemeral Workspace                 |
|                                            v                                            |
|                                 [ scanner_workspaces ]                                  |
|                              (/tmp/thread-trace/workspaces)                             |
|                                                                                         |
+-----------------------------------------------------------------------------------------+
```

1. **`frontend` Container:** Next.js application handling user UI, file upload dialogs, and report visualization.
2. **`backend` Container:** FastAPI application coordinating upload validation, safe ZIP extraction, scan dispatching, finding normalization, MongoDB persistence, and AI enrichment.
3. **`mongodb` Container:** MongoDB 7 database storing sanitized scan findings, scan metadata, and scan status records. Never exposed directly to the scanner or frontend.
4. **`scanner` Container:** Dedicated worker container packaging all static analysis engines (`semgrep`, `bandit`, `gitleaks`, `osv-scanner`, `custom-rules`). Operates with zero host privileges, no network egress, read-only rootfs, and non-root UID 10001.

---

## 2. Container Boundaries & Isolation Invariants

| Security Property | Scanner Worker (`scanner`) | Application Backend (`backend`) | Database (`mongodb`) |
|---|---|---|---|
| **Base Image** | `python:3.12-slim` | `python:3.12-slim` | `mongo:7` |
| **User Identity** | `scanner` (`UID:GID 10001:10001`) | `appuser` / unprivileged | `mongodb` (UID 999) |
| **Root Filesystem** | `read_only: true` | `read_only: false` (or ro + tmpfs) | Read-write volume |
| **Capabilities** | `cap_drop: [ALL]` | `cap_drop: [ALL]` | Standard mongo caps |
| **New Privileges** | `no-new-privileges:true` | `no-new-privileges:true` | Standard |
| **Network Egress** | `none` or `internal: true` | Outbound AI API only | None (internal only) |
| **Access to MongoDB** | **STRICTLY PROHIBITED** | Read-write via `MONGODB_URI` | N/A |
| **Access to AI Secret** | **STRICTLY PROHIBITED** | Read-only `AI_API_KEY` | None |
| **Host Ports** | None exposed | `127.0.0.1:8000` | None (internal only) |

---

## 3. The Zero Code-Execution Invariant

Under no circumstances may uploaded repository source code be executed:
- **No Build Scripts:** `make`, `ninja`, `cmake`, `rake`, `ant`, etc., are never invoked on target source.
- **No Package Installers:** `pip install`, `npm install`, `yarn`, `poetry install`, `cargo build`, or `go build` are strictly prohibited during scan execution.
- **No Setup Hooks:** `setup.py`, `package.json` lifecycle hooks (`preinstall`, `postinstall`), and `.bashrc` / `.profile` files are treated as inert text.
- **Parsers Only:** All scanner tools operate purely as static abstract syntax tree (AST) parsers, pattern matching engines, and manifest readers.

---

## 4. Workspace & Data Flow

```
[ Untrusted Client ]
       | (POST /api/v1/scans/upload)
       v
+------------------+
|     backend      | 1. Stream ZIP to /tmp/thread-trace/uploads/<scan_id>.zip
| (FastAPI / Dev B)| 2. Validate ZIP safety (ZIP bomb, Zip Slip, symlinks, ratios)
+------------------+ 3. Extract to /tmp/thread-trace/workspaces/<scan_id>/source
       |
       | 4. Trigger scan execution on scanner worker
       v
+------------------+
|     scanner      | 5. Mount /workspaces/<scan_id>/source as READ-ONLY (:ro)
| (Worker / Dev C) | 6. Run Semgrep, Bandit, Gitleaks, OSV, Custom Rules
+------------------+ 7. Write raw results to /workspaces/<scan_id>/output.json
       |
       | 8. Read raw results & unmount
       v
+------------------+
|     backend      | 9. Normalize findings via Dev C's normalizer.py
| (FastAPI / Dev B)| 10. Redact secrets in-memory via security.py
+------------------+ 11. Clean workspace (rm -rf /workspaces/<scan_id>)
       |             12. Store sanitized findings in MongoDB
       v
+------------------+
|     mongodb      | 13. Persist sanitized report (TTL index 30 days)
+------------------+
```

---

## 5. Failure Isolation

- If any individual scanner binary crashes, segfaults, times out, or runs out of memory:
  1. The scanner container process supervision captures stdout/stderr and exits with structured error.
  2. The backend records that scanner as `failed` or `partial`.
  3. The other 4 scanner results are preserved and delivered to the user.
  4. The container's resource bounds prevent host kernel OOM cascading to `backend` or `mongodb`.
