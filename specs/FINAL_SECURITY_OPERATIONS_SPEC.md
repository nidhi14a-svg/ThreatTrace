# Final Security Operations Specification

**File:** `specs/FINAL_SECURITY_OPERATIONS_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Targets:** `README.md`, `Makefile`, `docker-compose.yml`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 6, Task 6.8)  
**Status:** APPROVED & OPERATIONAL  

---

## 1. Overview & Operational Principles

This specification establishes standard operating procedures (SOP) for running, testing, monitoring, securing, and troubleshooting the Thread Trace platform.

### Operational Principles:
1. **Zero Cleartext Credentials:** Never commit real secrets, API keys, or private keys to repositories, configuration files, or docker layers.
2. **Least Privilege Runtime:** Scanner containers run unprivileged (`user: "10001:10001"`, `cap_drop: ALL`, `read_only: true`).
3. **Bounded Blast Radius:** Strict CPU, memory, PID, and execution timeout constraints prevent runaway scans from impacting host availability.
4. **Idempotent Ephemeral Cleanliness:** Temporary workspaces are automatically swept after scan completion or TTL expiry.

---

## 2. Startup & Deployment Procedures

### 2.1 Prerequisites
- **Node.js:** 20+ LTS or 22+
- **Python:** 3.12+ (64-bit)
- **Docker & Docker Compose:** v2.20+ (for containerized deployment)
- **Memory & Storage:** Min 4 GB RAM, 10 GB free disk space

### 2.2 Local Environment Setup
```powershell
# 1. Clone repository and navigate to root
cd C:\Users\nidhi\Desktop\mini

# 2. Copy environment template
cp .env.example .env

# 3. Install frontend dependencies
cd frontend; npm install; cd ..

# 4. Install backend dependencies
cd backend; python -m pip install -r requirements.txt; cd ..
```

### 2.3 Containerized Startup via Docker Compose
```powershell
# Build all container images (Frontend, Backend, Scanner Worker)
make build

# Start services in detached mode
make up

# Check status of running containers
docker compose ps

# Inspect logs
make logs
```

### 2.4 Service Health Checks
- **Frontend:** `http://localhost:3000`
- **Backend API:** `http://localhost:8000/health` (returns `{"status":"ok"}`)
- **API Documentation:** `http://localhost:8000/docs`
- **MongoDB:** Internal `mongodb:27017`

---

## 3. Scanner Operations & CLI Runner

### 3.1 Tool Availability & Version Verification
Verify tool availability across static scanners:
```powershell
# In containerized environment
make scanner-versions

# Or directly via Python
python -m backend.app.scanners.worker_runner --check-tools
```

### 3.2 Executing Worker Analysis Standalone
```powershell
# Run all scanners against a local target directory
python -m backend.app.scanners.worker_runner `
  --workspace C:\path\to\target `
  --output C:\path\to\results.json `
  --scanners all `
  --timeout 60
```

---

## 4. Testing & Verification Commands

```powershell
# Run complete backend test suite
cd backend
pytest -v

# Run focused security tests
pytest tests/test_zip_security.py -v
pytest tests/test_redaction_verification.py -v
pytest tests/test_end_to_end_security.py -v
pytest tests/test_delete_retention.py -v
pytest tests/test_finding_compatibility.py -v
pytest tests/test_scanner_report_mapping.py -v
```

---

## 5. Resource Controls & Limits

| Service | CPU Limit | Memory Limit | Process (PID) Limit | Storage / Mount Limits |
|---|---|---|---|---|
| **Frontend** | 1.0 CPU | 1,024 MB | 100 | Ephemeral |
| **Backend** | 1.5 CPUs | 1,024 MB | 150 | Ephemeral upload buffer |
| **MongoDB** | 1.0 CPU | 1,024 MB | 100 | Named volume `mongodb_data` |
| **Scanner Worker** | 2.0 CPUs | 2,048 MB | 150 | `read_only: true`, 64MB `tmpfs` |

---

## 6. Retention & Workspace Cleanup Operations

```powershell
# Sweep expired workspaces (older than 1800s TTL)
make clean-workspaces

# Run dry-run cleanup audit without deleting
python scripts/cleanup_workspaces.py --dry-run
```

---

## 7. Troubleshooting Guide

| Symptom / Error | Root Cause | Remediation Procedure |
|---|---|---|
| `Docker daemon unavailable` | Docker Desktop service not started on host. | Run tests in local mode (`pytest -v`). For deployment, start Docker Desktop and ensure Hyper-V / WSL2 engine is active. |
| `Scanner binary unavailable` | Scanner CLI not installed in local host path. | Normal on Windows host; external binaries are pre-packaged inside `Dockerfile.scanner`. Use Python test mocks or Docker worker. |
| `TypeError: unexpected argument 'timeout'` | Scanner adapter initialized with wrong kwarg. | Corrected: Semgrep, Bandit, Secrets, Dependency use `timeout_seconds`; CustomRules uses `timeout`. |
| `ScannerTimeoutExpired` | Target repository exceeds 60s per-tool limit. | Increase `SCANNER_TIMEOUT_SECONDS` in `.env` for large repositories. |
| `ZipSecurityValidationError: Zip Slip` | Malicious archive member contains `../` traversal. | Expected rejection. Quarantine the archive. |
| `ZipSecurityValidationError: Bomb` | Archive compression ratio exceeds 100:1. | Expected rejection. Verify archive contents. |
| `WorkspaceSecurityError` | Path breakout detected in workspace ID. | Ensure scan IDs are alphanumeric/hyphens without slashes. |
