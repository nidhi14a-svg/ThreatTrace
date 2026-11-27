# Scanner Secrets and Configuration Specification

- **Document:** `specs/SCANNER_SECRETS_CONFIG_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target Files:** `.env.example`, `.gitignore`, `docker-compose.yml`
- **Status:** Approved Specification (Phase 4, Task 4.9)
- **Version:** 1.0.0

---

## 1. Zero Secrets in Images and Containers

Under no circumstances should API keys, database credentials, or private certificates be baked into Docker images, committed to Git repositories, or passed to the scanner worker container.

### Enforced Principles:
1. **`.env` Ignored in Version Control:**
   - `.env` must be explicitly listed in `.gitignore`.
2. **Clean `.env.example` Template:**
   - `.env.example` provides default configuration variable names and safe defaults with empty credential fields.
3. **Quarantined Scanner Environment:**
   - The scanner worker container receives **ZERO secret environment variables**.
   - Variables like `MONGODB_URI`, `AI_API_KEY`, and `JWT_SECRET` are passed solely to `backend` and NEVER to `scanner`.

---

## 2. Environment Variable Inventory

| Variable Name | Required By | Secret? | Default Value | Description |
|---|---|---|---|---|
| `MONGODB_URI` | `backend` | Yes | `mongodb://mongodb:27017` | Internal MongoDB connection string |
| `DATABASE_NAME` | `backend` | No | `thread_trace` | Target database name |
| `BACKEND_PORT` | `backend` | No | `8000` | Host port for FastAPI backend |
| `FRONTEND_PORT` | `frontend` | No | `3000` | Host port for Next.js frontend |
| `NEXT_PUBLIC_API_URL` | `frontend` | No | `http://localhost:8000` | Browser API gateway address |
| `AI_API_KEY` | `backend` | Yes | `""` | Google Gemini API key (sanitized findings only) |
| `AI_MODEL` | `backend` | No | `gemini-1.5-pro` | Target AI model name |
| `UPLOAD_DIRECTORY` | `backend` | No | `/tmp/thread-trace/uploads` | Path for temporary archive uploads |
| `MAX_UPLOAD_SIZE` | `backend` | No | `104857600` | Maximum upload size in bytes (100 MB) |
| `SCANNER_TIMEOUT_SECONDS` | `backend` | No | `60` | Maximum timeout per scanner execution |
| `GLOBAL_SCAN_TIMEOUT_SECONDS` | `backend` | No | `300` | Maximum timeout for entire scan pipeline |
| `WORKSPACE_BASE_DIR` | `backend`, `scanner` | No | `/tmp/thread-trace/workspaces` | Shared volume for workspaces |
| `WORKSPACE_TTL_SECONDS` | `backend`, scripts | No | `1800` | TTL before orphaned workspace cleanup (30 min) |

---

## 3. Scanner Worker Environment Whitelist

The scanner container environment is restricted to non-sensitive runtime parameters:

```yaml
scanner:
  environment:
    - PYTHONUNBUFFERED=1
    - PYTHONDONTWRITEBYTECODE=1
    - HOME=/tmp
    - TMPDIR=/tmp
    - SEMGREP_SETTINGS_CACHE_DISABLED=1
    - SEMGREP_SEND_METRICS=off
```
