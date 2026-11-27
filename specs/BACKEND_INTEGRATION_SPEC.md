# Backend Scanner Integration Specification

**File:** `specs/BACKEND_INTEGRATION_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Collaborator:** Dev B — Backend Orchestration, API & Database  
**Implementation Targets:** `backend/app/scanners/worker_runner.py`, `backend/app/scanners/workspace.py`, `backend/app/scanners/base_scanner.py`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 6, Task 6.1)  
**Status:** APPROVED & IMPLEMENTED  

---

## 1. Overview & Objectives

This specification defines the formal backend integration interface between the scanner execution infrastructure (implemented by Dev C) and the scan orchestration, persistence, and API lifecycle (owned and implemented by Dev B).

The fundamental architectural principle is **strict process and container isolation**:
1. The **FastAPI backend** (Dev B) manages client uploads, archive validation, scan records in MongoDB, and asynchronous job queuing.
2. The **Dedicated Scanner Worker** (Dev C) executes static analysis tools (Semgrep, Bandit, Gitleaks, OSV-Scanner, and Custom Rules) in an unprivileged, read-only, air-gapped environment.
3. The boundary between the backend and scanner worker is governed by a well-defined filesystem and process contract, ensuring that neither service compromises the operational stability or security boundaries of the other.

---

## 2. Dev B vs. Dev C Ownership Boundary

To preserve architectural integrity and avoid merge conflicts or duplicated responsibilities:

| Responsibility | Owner | Primary Implementation Files |
|---|---|---|
| HTTP Upload Route & Multipart Handling | Dev B | `backend/app/api/routes/scans.py`, `upload_service.py` |
| Archive Validation & Safe Extraction | Dev B | `backend/app/services/extraction_service.py`, `backend/app/utils/file_utils.py` |
| Database Persistence (MongoDB / Motor) | Dev B | `backend/app/models/`, `backend/app/core/database.py` |
| Scan Job Lifecycle (`pending` -> `completed`) | Dev B | `backend/app/services/scan_service.py` |
| API Response Serialization & Report Routing | Dev B | `backend/app/services/report_service.py`, `backend/app/api/routes/reports.py` |
| Ephemeral Workspace Filesystem Protocol | Dev C | `backend/app/scanners/workspace.py` |
| Static Scanner Adapters & CLI Invocations | Dev C | `backend/app/scanners/*.py` |
| Scanner Execution Result Contract | Dev C | `backend/app/scanners/base_scanner.py` |
| Worker Process Runner & CLI Entrypoint | Dev C | `backend/app/scanners/worker_runner.py` |
| In-Memory Secret Redaction & Finding Normalizer | Dev C | `backend/app/scanners/normalizer.py`, `app/core/security.py` |
| Container Airgap & Resource Boundaries | Dev C | `backend/Dockerfile.scanner`, `docker-compose.yml` |

**Strict Rule:** Dev C does not modify `backend/app/services/scan_service.py`, `backend/app/services/extraction_service.py`, or database models without explicit Dev B coordination and approval.

---

## 3. Approved Orchestration Boundary & Invocation Interface

Dev B's orchestrator interacts with Dev C's scanner infrastructure through two approved patterns:

### Pattern A: Containerized Production Invocation (Recommended for Deployment)
The FastAPI backend invokes the isolated scanner worker container using Docker Compose / Docker CLI over a shared volume mount (`scanner_workspaces`):

```bash
docker compose run --rm \
  -v scanner_workspaces:/tmp/thread-trace/workspaces \
  scanner \
  --workspace /tmp/thread-trace/workspaces/<scan_id>/source \
  --output /tmp/thread-trace/workspaces/<scan_id>/output/raw_results.json \
  --scanners all \
  --timeout 60
```

1. **Input:** Dev B extracts uploaded source code into `<workspace_dir>/source/`. This directory is mounted **read-only** (`:ro`) into the scanner worker container.
2. **Execution:** The scanner worker runs as unprivileged user `10001:10001` with `cap_drop: ALL`, `read_only: true`, and no network access.
3. **Output:** The scanner worker writes the consolidated, normalized, redacted JSON payload to `<workspace_dir>/output/raw_results.json`.
4. **Ingestion:** Dev B reads `raw_results.json`, updates the scan status in MongoDB, and triggers AI enrichment if requested.
5. **Cleanup:** Dev B invokes `WorkspaceManager.cleanup_workspace(scan_id)` or relies on the background retention sweeper (`scripts/cleanup_workspaces.py`).

### Pattern B: Programmatic Asynchronous Invocation (For Local Dev / In-Process Testing)
For environments where Docker Desktop is unavailable or during fast unit/integration testing:

```python
from app.scanners.worker_runner import run_scanners, process_and_normalize_results

# 1. Execute static analysis scanners concurrently with fault isolation
raw_results = await run_scanners(
    workspace=str(workspace_source_dir),
    selected_scanners=["all"],
    timeout=60,
)

# 2. Normalize findings, apply deduplication, suppression, and secret redaction
scan_payload = process_and_normalize_results(raw_results)
```

The resulting dictionary matches the JSON structure emitted by the CLI runner.

---

## 4. Contract Specifications: `ScannerExecutionResult`

Every scanner adapter adheres strictly to the `BaseScanner` interface (`backend/app/scanners/base_scanner.py`):

```python
class ScannerExecutionResult(BaseModel):
    scanner_name: str
    status: Literal["success", "partial", "failed", "skipped"]
    findings: list[dict[str, Any]] = Field(default_factory=list)
    duration_seconds: float = 0.0
    error: str | None = None
```

### Invariants:
1. **No Raw Unhandled Exceptions:** The `safe_scan()` decorator/wrapper catches all tool-level exceptions (`CalledProcessError`, `TimeoutExpired`, `FileNotFoundError`, `JSONDecodeError`) and encapsulates them into a structured `ScannerExecutionResult` with `status="failed"`.
2. **Scanner Name Immutability:** `scanner_name` must be one of: `"semgrep"`, `"bandit"`, `"gitleaks"`, `"osv-scanner"`, `"custom-rules"`.
3. **Execution Limits:** Per-scanner timeout defaults to `60` seconds (`SCANNER_TIMEOUT_SECONDS`). Timeouts result in `status="failed"` and an informative error message without blocking other concurrent scanners.
4. **Duration Tracking:** Each scanner measures real wall-clock execution duration in seconds.

---

## 5. Fault Isolation & Status Aggregation

When executing multiple scanners, individual scanner failures must **never** fail the entire scan job. The aggregate status is computed via `aggregate_scanner_statuses()`:

| Scanner Outcomes | Overall Aggregated Status | Meaning |
|---|:---:|---|
| All scanners succeed (`success`) | `"success"` | Complete scan completed without tool errors. |
| At least one succeeds/skips, at least one fails | `"partial"` | Partial scan success; available findings preserved and reported. |
| All scanners skipped (`skipped`) | `"skipped"` | Workspace contained no applicable source files. |
| All scanners fail (`failed`) | `"failed"` | Systemic execution failure; error details aggregated for diagnosis. |

---

## 6. Workspace Filesystem Layout

The filesystem layout is strictly managed by `WorkspaceManager` (`backend/app/scanners/workspace.py`):

```
/tmp/thread-trace/workspaces/
└── <scan_id>/
    ├── source/              <-- Extracted code (Read-Only to scanner worker)
    │   ├── app/
    │   └── requirements.txt
    └── output/              <-- Output directory (Writable only by scanner worker)
        └── raw_results.json
```

- Path traversal attempts in `<scan_id>` (e.g. `../`, `/`, `\`) raise `WorkspaceSecurityError`.
- Base workspace directory is configurable via `WORKSPACE_BASE_DIR` environment variable.
