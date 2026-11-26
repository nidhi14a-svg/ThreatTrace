# Secure Scan Execution Specification

- **Document:** `specs/SECURE_SCAN_EXECUTION_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator / Implementation Owner:** Dev B (Backend Developer)
- **Implementation References:** `backend/app/core/security.py`, `.env.example`
- **Status:** Approved Specification (Phase 1)
- **Version:** 1.0.0

---

## 1. Executive Summary & Threat Model

The core function of Thread Trace involves accepting arbitrary, unverified source-code archives from untrusted external users and subjecting them to automated security analysis. Consequently, **the uploaded source code must be treated as hostile code**.

```
+-------------------------------------------------------------------------+
|                              HOST SYSTEM                                |
|                                                                         |
|  +------------------+         +--------------------------------------+  |
|  |  FastAPI Backend |         |           SCANNER SANDBOX            |  |
|  |  (Dev B Service) |         |                                      |  |
|  |                  |         |  - Network: NONE (Air-gapped)        |  |
|  |  1. Safe Unpack  |         |  - User: Non-root (UID 10001)        |  |
|  |  2. Mount Read-  | ------> |  - Rootfs: READ-ONLY                 |  |
|  |     Only (:ro)   |         |  - Cap Drop: ALL                     |  |
|  |  3. Parse Output |         |  - PIDs Limit: 100                   |  |
|  |  4. Immediate    | <------ |  - Memory Limit: 1.5 GB              |  |
|  |     Wipe Temp    |         |  - Timeouts: 60s hard limit          |  |
|  +------------------+         +--------------------------------------+  |
|           |                                                             |
|           v                                                             |
|   [ MongoDB Store ] (Findings only, secrets REDACTED, zero source code)  |
+-------------------------------------------------------------------------+
```

### Threat Vectors Mitigated:
1. **Remote Code Execution (RCE) via Build Hooks:** Hostile repositories containing weaponized `setup.py`, `package.json` install scripts (`preinstall`), or Makefile targets executed during analysis.
2. **Denial of Service (DoS):** Malicious source files engineered to induce unbounded CPU utilization, algorithmic complexity attacks (ReDoS), or memory exhaustion in scanner parsers.
3. **Privilege Escalation:** Exploitation of zero-day vulnerabilities in underlying scanner engines (Semgrep, Bandit, Gitleaks, OSV-Scanner) to gain root or host filesystem access.
4. **Data Exfiltration / Network Probing:** Scanners weaponized to pivot into the internal Docker network, probe MongoDB, or exfiltrate environment credentials to command-and-control servers.
5. **Credential Leakage in Logs / AI Prompts:** Unredacted API keys or database connection strings discovered in uploaded code leaking into application logs or third-party AI provider requests.

*Phase 1 Rule:* This specification documents security requirements; execution pipeline implementation is reserved for future phases.

---

## 2. Resource Limits

To prevent resource exhaustion and guarantee multi-tenant operational stability, all scanner container runs or child processes must be constrained by rigid, enforceable resource ceilings:

| Resource Metric | Default Ceiling | Maximum Permissible | Enforcement Mechanism |
|---|---|---|---|
| **Memory (RAM)** | 1.0 GB | 1.5 GB | Docker `--memory=1.5g` / cgroups `memory.max` |
| **Swap Memory** | 0 MB (Disabled) | 0 MB | Docker `--memory-swap=1.5g` (prevents disk thrashing) |
| **CPU Allocation** | 1.0 Core | 2.0 Cores | Docker `--cpus=1.5` / cgroups `cpu.max` |
| **Process Limit (PIDs)** | 64 processes | 100 processes | Docker `--pids-limit=100` (prevents fork bombs) |
| **Temporary Disk Write** | 30 MB (tmpfs) | 50 MB (tmpfs) | Docker `--tmpfs /tmp:rw,noexec,nosuid,size=50m` |
| **Max Output File Size** | 10 MB | 25 MB | Truncation limit on captured stdout/stderr JSON |

If a scanner process exceeds the memory ceiling, the host kernel OOM killer must terminate the scanner container immediately, and the backend must record a structured `SCANNER_RESOURCE_EXCEEDED` error without crashing the parent application.

---

## 3. Execution Timeouts

Unbounded execution represents a severe vulnerability. Scanners can hang due to catastrophic backtracking in regex engines, circular AST references, or infinite loops in target code:

| Scope | Timeout Value | Action upon Expiration |
|---|---|---|
| **Per-File Scanner Timeout** | 10 seconds | Scanner aborts current file, logs warning, and continues next file. |
| **Per-Scanner Module Timeout** | 60 seconds | Backend terminates scanner container via `SIGTERM`, followed by `SIGKILL` after a 5-second grace period. |
| **Global Scan Job Timeout** | 300 seconds (5 min) | Backend orchestrator marks overall scan as `FAILED`, cleans workspace, and returns timeout response. |

*Implementation Rule:* Timeout values must be configurable via environment variables (`SCANNER_TIMEOUT_SECONDS=60`, `GLOBAL_SCAN_TIMEOUT_SECONDS=300`) with safe defaults.

---

## 4. Restricted Network Access (Network Isolation)

1. **Air-Gapped Scanner Execution:**
   - Scanner containers must execute with `network_mode: none`.
   - All external ingress and egress traffic is physically disabled at the Docker network level.
2. **Prohibited Network Activity:**
   - Scanners are strictly prohibited from resolving external DNS queries, connecting to public HTTP/HTTPS endpoints, or making network probes to verify discovered credentials.
   - Scanners must have zero access to the backend API network or the MongoDB database network (`thread_trace_default` network is detached).
3. **Offline Advisory Handling (OSV-Scanner):**
   - OSV-Scanner must operate in `--offline` mode using a local read-only vulnerability database snapshot or volume, preventing outbound requests during live scan execution.

---

## 5. Unprivileged Scanner Execution

Scanner containers must never run with root privileges:

1. **Non-Root User Context:**
   - Dedicated service user: `UID 10001`, `GID 10001` (named `scanner`).
   - Docker configuration: `user: "10001:10001"`.
2. **Privilege Dropping:**
   - `cap_drop: [ALL]` — Drop all Linux capabilities (including `CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_CHOWN`, `CAP_SETUID`).
   - `security_opt: ["no-new-privileges:true"]` — Prohibit child processes from elevating privileges via setuid binaries.
3. **Read-Only Root Filesystem:**
   - `read_only: true` — The root filesystem of the scanner container must be mounted read-only (`ro`).
   - Scratch writes are restricted solely to an in-memory `tmpfs` mounted at `/tmp` with `noexec,nosuid,nodev` flags.

---

## 6. Workspace Isolation & Prohibited Execution

### 6.1 Workspace Isolation
- Each uploaded archive is extracted into a dedicated, ephemeral workspace directory identified by a secure random UUIDv4:
  `/tmp/thread-trace/workspaces/<scan_id>/`
- The workspace directory is mounted into the scanner container strictly as **read-only** (`:ro`):
  `volumes: ["/tmp/thread-trace/workspaces/<scan_id>:/workspace:ro"]`
- Scanner containers cannot write, alter, or delete any file in the workspace directory.

### 6.2 Strict Prohibition of Source-Code Execution
- **Zero Target Code Execution:** Under NO circumstances should any uploaded file, build script, package installer, or test suite be executed on the host, in the backend container, or in the scanner container.
- **Tools Run As Parsers Only:** Scanners operate strictly as static AST parsers and file readers. No `python setup.py build`, `pip install`, `npm install`, `make`, or script execution is ever permitted on scanned code.

---

## 7. Temporary File Handling, Cleanup & Retention

### 7.1 Ephemeral File Lifecycle
```
[ ZIP Upload ] -> Stored at /tmp/thread-trace/uploads/<scan_id>.zip (0600)
       |
       v
[ Safe Extraction ] -> Extracted to /tmp/thread-trace/workspaces/<scan_id>/ (0700)
       |
       v
[ Scanner Execution ] -> Mounts workspace as :ro, writes output to memory
       |
       v
[ Immediate Wipe ] -> rm -rf /tmp/thread-trace/workspaces/<scan_id>/
                     rm -f /tmp/thread-trace/uploads/<scan_id>.zip
```

### 7.2 Cleanup Guarantees
- Cleanup of both the uploaded archive and the extracted workspace directory must occur immediately upon scan completion or failure inside a mandatory Python `finally:` block.
- **Orphan Sweeper:** A periodic background task sweeps `/tmp/thread-trace/` every 15 minutes to delete any workspace directory older than 30 minutes, handling unexpected system crashes or container terminations.

### 7.3 Data Retention Policies
- **Source Code:** NEVER permanently retained on disk or in the database.
- **Normalized Findings & Reports:** Stored in MongoDB with sensitive evidence redacted.
- **Report Retention Window:** Findings and scan reports are retained according to the retention window (default: 30 days) before automatic expiration via MongoDB TTL index.

---

## 8. Secret Redaction Standard

To prevent customer or third-party credentials from entering permanent storage, logs, or external AI models:

1. **In-Memory Redaction:**
   - All secret scanner adapters (Gitleaks, Semgrep, custom rules) must execute a redaction filter in memory before constructing the `Finding` object.
2. **Redaction Pattern:**
   - Raw matched secret strings must be sanitized using a mask pattern:
     - For known structured tokens: Preserve format prefix, mask secret body (e.g., `AKIA****************`).
     - For unstructured passwords/secrets: Replace entirely with `[REDACTED_SECRET]`.
3. **Log Sanitization:**
   - Application loggers must never print raw finding evidence containing unredacted tokens.
4. **AI Sanitization Boundary:**
   - When findings are passed to Dev B's AI service (`ai_service.py`), only sanitized titles, descriptions, and redacted evidence may be transmitted. Full source-code files must NEVER be sent to the AI provider.

---

## 9. Environment-Variable & Credential Protection

Scanner processes must be completely quarantined from backend secrets:

1. **Sanitized Environment:**
   - Scanner containers must NOT inherit host or backend environment variables.
   - The following critical secrets must be explicitly excluded from scanner environments:
     - `MONGODB_URI`
     - `AI_API_KEY`
     - `JWT_SECRET` / authentication keys
     - Host filesystem paths or cloud provider tokens
2. **Whitelisted Environment Variables Only:**
   - Scanners are supplied with a strictly minimal, whitelisted set of environment variables:
     ```bash
     PATH=/usr/local/bin:/usr/bin:/bin
     LANG=C.UTF-8
     LC_ALL=C.UTF-8
     HOME=/tmp
     TMPDIR=/tmp
     ```
