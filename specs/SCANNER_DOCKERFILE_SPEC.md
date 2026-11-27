# Scanner Dockerfile Specification

- **Document:** `specs/SCANNER_DOCKERFILE_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target File:** `backend/Dockerfile.scanner`
- **Status:** Approved Specification (Phase 4, Task 4.2)
- **Version:** 1.0.0

---

## 1. Objectives & Threat Mitigation

The scanner worker Docker image packages static analysis tools into a minimal, repeatable, and locked-down container.

### Threat Mitigations:
1. **Supply Chain Tampering:** Pinned versions for all scanner binaries and Python libraries.
2. **Container Breakout:** Non-root execution (`UID 10001:10001`), no setuid/setgid binaries, dropped capabilities.
3. **Immutability:** Read-only root filesystem compatible; only ephemeral write access granted to in-memory `/tmp`.
4. **Credential Isolation:** Image contains zero credentials, secrets, tokens, or environment overrides.

---

## 2. Base Image & Tooling Specifications

| Component | Specification | Purpose | Source / Installation |
|---|---|---|---|
| **Base OS** | `python:3.12-slim-bookworm` | Minimal Debian base with modern Python 3.12 | Official Docker Hub |
| **System Tools** | `ca-certificates`, `curl`, `git` | Git history analysis for Gitleaks; cert validation | Debian apt repository |
| **Semgrep** | `semgrep==1.99.0` (pinned) | Multi-language AST static analysis | PyPI |
| **Bandit** | `bandit==1.8.0` (pinned) | Python AST vulnerability scanner | PyPI |
| **Gitleaks** | `v8.21.2` (pinned) | Secret detection Go static binary | Official GitHub Releases |
| **OSV-Scanner** | `v1.9.0` (pinned) | Dependency vulnerability scanner Go binary | Official GitHub Releases |
| **Custom Rules** | Thread Trace Custom Pack | 16 native AST & regex rules | `backend/app/scanners/` |

---

## 3. User Identity & Permission Hardening

1. **Dedicated User Creation:**
   ```dockerfile
   RUN groupadd -g 10001 scanner && \
       useradd -u 10001 -g 10001 -m -s /sbin/nologin -d /home/scanner scanner
   ```
2. **Directory Permissions:**
   - Application code `/app` owned by `root:root` with read-only permissions `0555` (no runtime tampering).
   - Scratch directory `/tmp` mounted via tmpfs or restricted permissions `1777`.
   - User home directory `/home/scanner` read-only or empty.
3. **Execution Context:**
   ```dockerfile
   USER 10001:10001
   WORKDIR /tmp
   ```

---

## 4. Entrypoint & Worker Runner Interface

The scanner worker exposes a Python-based worker runner:
`python -m app.scanners.worker_runner`

Arguments:
- `--workspace <path>`: Path to mounted target source repository (read-only).
- `--output <path>`: Path to destination JSON results file.
- `--scanners <list>`: Comma-separated list of scanners to execute (`semgrep,bandit,gitleaks,osv,custom`).
- `--timeout <int>`: Per-scanner execution timeout in seconds (default: 60).

In long-running daemon mode (if deployed as a container service), the container listens on an internal socket or loops over job requests in the shared volume without requiring external network exposure.
