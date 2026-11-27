# DevOps Commands Specification

- **Document:** `specs/DEVOPS_COMMANDS_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target File:** `Makefile`
- **Status:** Approved Specification (Phase 4, Task 4.8)
- **Version:** 1.0.0

---

## 1. Standard Makefile Commands

The root `Makefile` provides unified targets for building, running, testing, and maintaining Thread Trace services.

### Targets:

1. **`install`:**
   - Installs frontend and backend dependencies for local development.
2. **`build`:**
   - Builds all Docker images (frontend, backend, scanner worker).
3. **`build-scanner`:**
   - Builds only the dedicated scanner worker image (`backend/Dockerfile.scanner`).
4. **`up` / `docker-up`:**
   - Starts all services in the background (`docker compose up -d`).
5. **`down` / `docker-down`:**
   - Stops all containers and detaches networks (`docker compose down`).
6. **`test`:**
   - Executes backend pytest test suite (`cd backend && pytest -q`).
7. **`scanner-versions`:**
   - Runs a quick version audit on all static analysis tools inside the scanner container.
8. **`clean-workspaces`:**
   - Invokes `scripts/cleanup_workspaces.py` to remove stale workspace files older than TTL.
9. **`logs`:**
   - Displays combined logs across all services (`docker compose logs -f`).
10. **`clean`:**
    - Removes local build caches (`.pytest_cache`, `.next`).
