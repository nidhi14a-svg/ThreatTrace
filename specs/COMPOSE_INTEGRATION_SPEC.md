# Docker Compose Integration Specification

- **Document:** `specs/COMPOSE_INTEGRATION_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target File:** `docker-compose.yml`
- **Status:** Approved Specification (Phase 4, Task 4.3)
- **Version:** 1.0.0

---

## 1. Multi-Container Service Layout

`docker-compose.yml` defines the four isolated services required for Thread Trace:

```yaml
services:
  frontend:
    # Next.js UI
    ports:
      - "${FRONTEND_PORT:-3000}:3000"
    networks:
      - app-net

  backend:
    # FastAPI Application & Orchestration
    ports:
      - "127.0.0.1:${BACKEND_PORT:-8000}:8000"
    networks:
      - app-net
      - db-net
      - scanner-net
    volumes:
      - scanner_workspaces:/tmp/thread-trace/workspaces

  mongodb:
    # Storage Engine (Air-gapped)
    image: mongo:7
    networks:
      - db-net
    volumes:
      - mongodb_data:/data/db

  scanner:
    # Dedicated Scanner Worker (Air-gapped)
    build:
      context: ./backend
      dockerfile: Dockerfile.scanner
    networks:
      - scanner-net
    volumes:
      - scanner_workspaces:/tmp/thread-trace/workspaces
```

---

## 2. Network Topology & Segregation Rules

Three distinct Docker bridge networks enforce strict isolation:

1. **`app-net`:**
   - Connects: `frontend` and `backend`.
   - Purpose: Ingress API traffic from Next.js SSR / client to FastAPI backend.
   - External access: Host port 3000 exposed for browser access.
2. **`db-net` (`internal: true`):**
   - Connects: `backend` and `mongodb`.
   - Purpose: Database query traffic via Motor/PyMongo.
   - Isolation: `frontend` and `scanner` containers CANNOT resolve or communicate with MongoDB. No external internet routing.
3. **`scanner-net` (`internal: true`):**
   - Connects: `backend` and `scanner`.
   - Purpose: Scan job dispatch and health probes.
   - Isolation: `mongodb` and `frontend` CANNOT reach `scanner`. `scanner` CANNOT reach MongoDB. No external internet routing.

---

## 3. Shared Volumes

1. **`mongodb_data`:**
   - Backed by named volume for database persistence.
2. **`scanner_workspaces`:**
   - Mounted at `/tmp/thread-trace/workspaces` in both `backend` and `scanner`.
   - Backend extracts uploaded source files to subfolder `<scan_id>/source`.
   - Scanner worker mounts `<scan_id>/source` as read-only.
   - Scanner worker writes result payload to `<scan_id>/output.json`.
   - Backend removes `<scan_id>` immediately upon completion.
