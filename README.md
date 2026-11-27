# Thread Trace

**AI-Assisted Source-Code Vulnerability Detection Platform**

Thread Trace is a secure, modular static application security testing (SAST) and software composition analysis (SCA) platform. It analyzes uploaded source code across five primary cybersecurity domains using dedicated static analyzers, normalizes findings into a unified data contract, applies in-memory secret redaction, and isolates scanner execution in an unprivileged, resource-bounded environment.

---

## Architecture Overview

Thread Trace enforces strict separation of concerns across three core service domains:

1. **Frontend (`frontend/`):** Next.js App Router, React, Tailwind CSS dashboard.
2. **Backend API (`backend/app/`):** Python FastAPI, Pydantic, Motor/MongoDB. Manages upload validation, scan job lifecycle, and AI enrichment boundaries.
3. **Dedicated Scanner Worker (`backend/Dockerfile.scanner`):** An isolated, unprivileged Linux container (UID 10001) with a read-only root filesystem, dropped capabilities (`cap_drop: ALL`), and an internal air-gapped network. Executes Semgrep, Bandit, Gitleaks, OSV-Scanner, and Custom AST rules.

---

## Five Cybersecurity Domains

Every detection maps to one of five project-level security domains:

| Domain | Scope & Focus | Primary Tools |
|---|---|---|
| **1. Secrets & Sensitive Information Management** | Hardcoded API keys, cloud tokens, database connection strings, private keys. | Gitleaks, Custom Secrets Rules |
| **2. Web Application Security** | SQL injection, command injection, path traversal, unsafe deserialization, XSS. | Semgrep, Bandit, Custom AST Rules |
| **3. Network & Communication Security** | Disabled TLS verification, cleartext HTTP communications, weak ciphers. | Bandit, Custom Network Rules |
| **4. Authentication & Access Control** | Broken authentication, hardcoded JWT secrets, weak password hashing algorithms. | Semgrep, Custom Auth Rules |
| **5. Dependency & Configuration Security** | Known CVEs/GHSAs in manifests, debug mode in production, permissive CORS wildcards. | OSV-Scanner, Custom Config Rules |

---

## Security Invariants & Defenses

- **Zero Untrusted Code Execution:** Uploaded source code, `setup.py`, Makefiles, package scripts, and build hooks are **never executed**. Analysis is strictly static (AST parsing and regex).
- **Archive Security Boundaries:**
  - Maximum upload size: 100 MB.
  - Maximum uncompressed extraction size: 250 MB.
  - Maximum entry count: 5,000 files.
  - Compression ratio bomb defense: Maximum 100:1 ratio.
  - Absolute paths and Zip Slip path traversal (`../`) are strictly rejected.
  - POSIX symlinks are rejected to prevent host filesystem breakout.
- **Secret Redaction:** High-entropy credentials, cloud keys, database passwords, and multiline RSA/EC private keys are automatically masked before finding persistence or report display.
- **AI Context Sanitization:** AI remediation models receive only sanitized, evidence-bounded (max 1,000 chars) finding summaries. Raw repositories and source trees are **never** transmitted to AI providers.
- **Ephemeral Workspaces:** Upload archives and extracted workspaces are placed in ephemeral directories with a 30-minute time-to-live (TTL) and purged automatically after scan completion.

---

## Prerequisites

- **Node.js:** 20+ LTS or 22+
- **Python:** 3.12+ (64-bit)
- **Docker & Docker Compose:** v2.20+ (for containerized deployment)

---

## Quick Start & Local Setup

### 1. Environment Configuration
Copy `.env.example` to `.env` and configure local values:
```powershell
cp .env.example .env
```
*Never commit real API keys, credentials, or private keys to source control.*

### 2. Frontend Setup
```powershell
cd frontend
npm install
npm run dev
```
Accessible at `http://localhost:3000`.

### 3. Backend Setup
```powershell
cd backend
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
- API Endpoint: `http://localhost:8000`
- Interactive OpenAPI Docs: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

### 4. Containerized Deployment via Docker Compose
```powershell
# Build container images
make build

# Start all four services (frontend, backend, mongodb, scanner)
make up

# Check service health and logs
make logs

# Stop services
make down
```

---

## Testing & Verification

Run the comprehensive automated test suite (unit, integration, security fixtures, archive defenses, redaction, and lifecycle cleanup):

```powershell
# Run full backend test suite
cd backend
pytest -v

# Run focused security tests
make test-security
```

---

## Scanner Limitations & Responsible Use

> [!WARNING]
> **Static Analysis Notice:**  
> Static security scanners evaluate syntactic patterns and known vulnerability databases. They **cannot guarantee the absence of security vulnerabilities** or determine runtime exploitability.

- **Cross-File Data Flow:** Complex data flows spanning asynchronous queues, ORM abstraction layers, or multiple microservices fall outside single-file AST limits.
- **Dynamic Vulnerabilities:** Race conditions, TOCTOU flaws, and memory corruption bugs require dynamic runtime analysis and fuzzing.
- **Unsupported Formats:** Compiled binaries (`.exe`, `.so`, `.class`), encrypted files, and nested archives are excluded from static inspection.
- **Manual Assessment:** Findings marked with `confidence: "low"` and critical authentication modules must be verified through manual code review and penetration testing.

---

## Security Operations & Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| `Docker daemon unavailable` | Docker Desktop service not started on host. | Run tests in local mode (`pytest -v`). For containerized deployment, start Docker Desktop. |
| `Scanner binary unavailable` | Scanner CLI not in host PATH. | Binaries are packaged inside the dedicated container image (`Dockerfile.scanner`). Use local test mocks or container runner. |
| `ZipSecurityValidationError` | Uploaded ZIP violated security rules (Zip Slip, bomb, excessive size). | Archive was safely quarantined and rejected. Check file structure and compression ratio. |
| `WorkspaceSecurityError` | Path traversal detected in workspace ID. | Ensure scan IDs are alphanumeric/hyphen characters without slashes. |
