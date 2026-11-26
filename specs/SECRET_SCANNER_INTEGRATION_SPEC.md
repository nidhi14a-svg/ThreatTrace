# Secret Scanner Integration Specification

- **Document:** `specs/SECRET_SCANNER_INTEGRATION_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator:** Dev B (Backend Developer)
- **Implementation File:** `backend/app/scanners/secrets_scanner.py`
- **Task Reference:** Phase 2, Task 2.4 — Secret Scanner Integration
- **Status:** Approved Specification & Implementation
- **Version:** 1.0.0

---

## 1. Executive Summary & Purpose

Hardcoded credentials, API keys, private keys, database connection strings, and tokens in source repositories represent immediate, severe attack vectors.

In Thread Trace, secret detection is dedicated to the canonical domain **Secrets & Sensitive Information Management** (mapped to `secrets` in the shared schema).

Task 2.4 implements `SecretsScanner` adhering to the common `BaseScanner` interface. It integrates **Gitleaks** as the primary detection engine (with detect-secrets compatibility considerations), executes Gitleaks in directory mode (`--no-git`), captures JSON output, normalizes paths to relative coordinates, handles Gitleaks' exit code semantics (exit code 1 on detected leaks), and enforces **strict in-memory credential redaction** so raw secrets never leak into logs, persistent findings, reports, or external AI models.

---

## 2. Engine Selection: Gitleaks vs. detect-secrets

| Evaluation Dimension | Gitleaks (Selected Primary) | detect-secrets (Secondary / Alternative) |
|---|---|---|
| **Architecture** | Single static precompiled Go binary | Python package with baseline plugin dependencies |
| **Ruleset** | 160+ token definitions (AWS, GCP, GitHub, Stripe, Private Keys) | Heuristic plugins + Shannon entropy calculations |
| **Directory Mode** | Native `gitleaks dir <path> --no-git` | Requires generating baseline file or wrapper |
| **Redaction Flag** | Native `--redact` flag | Requires post-processing filters |
| **Performance** | High-throughput concurrent regex/entropy engine | Slower AST/regex traversal on large repositories |
| **Decision** | **Primary Engine for Thread Trace** | Kept as secondary fallback pattern |

---

## 3. CLI Execution & Invocation Parameters

Gitleaks is executed via asynchronous subprocess execution (`asyncio.create_subprocess_exec`). Subprocess arguments are passed strictly as a validated list; `shell=True` is prohibited.

### 3.1 Default Command Structure
```bash
gitleaks dir <workspace_path> \
  --no-git \
  --report-format json \
  --report-path <temp_report_file> \
  --redact
```

### 3.2 Parameter Definitions
- **`dir <workspace_path>`:** Directs Gitleaks to evaluate the target directory directly as a filesystem tree.
- **`--no-git`:** Instructs Gitleaks not to look for a `.git` commit log, scanning raw files on disk.
- **`--report-format json`:** Formats the findings report as JSON.
- **`--report-path <path>`:** Directs report output to an isolated ephemeral report file.
- **`--redact`:** Native flag to mask matched secrets in the report.
- **`--config <path>`:** (Optional) Path to custom TOML ruleset.

---

## 4. Mandatory In-Memory Secret Redaction Guarantee

Under the Thread Trace Security Architecture:
1. **Never Expose Plaintext Secrets:** Even if Gitleaks runs with `--redact`, `SecretsScanner` applies a secondary, deterministic in-memory redaction pass over all findings.
2. **Finding Fields Redaction:**
   - `Secret` field: The matched secret is replaced with `"[REDACTED]"`. Raw secret strings are never retained in memory or stored in the finding dictionary.
   - `Match` / `evidence` field: Any occurrence of the secret token within surrounding source context is masked with `[REDACTED]`.
   - Known token patterns (AWS `AKIA...`, private key headers, bearer tokens) are subjected to regex scrubbing.
3. **Log & Diagnostic Safety:**
   - Application logs, stderr traces, and exception messages must never contain captured credentials.

---

## 5. Raw Finding Data Contract

In accordance with Phase 2 architecture, `SecretsScanner` emits **raw finding dictionaries** directly into `ScannerExecutionResult.findings`. Dev B's backend orchestrator owns subsequent normalization into the shared Pydantic `Finding` model.

### 5.1 Raw Finding Dictionary Schema
```python
{
    "scanner_name": "secrets",
    "rule_id": "gitleaks.aws-access-key-id",   # str: prefixed Gitleaks rule ID
    "title": "AWS Access Key ID",              # str: human-readable secret description
    "severity": "CRITICAL",                    # str: CRITICAL, HIGH, or MEDIUM
    "raw_category": "secrets",                 # str: domain category
    "file": "backend/app/core/config.py",      # str: strictly relative POSIX path within workspace
    "line": 14,                                # int | None: 1-indexed line number
    "end_line": 14,                            # int | None: ending line number
    "col": 18,                                 # int | None: starting column
    "end_col": 38,                             # int | None: ending column
    "evidence": "AWS_KEY = \"[REDACTED]\"",    # str: sanitized, redacted evidence (max 1000 chars)
    "entropy": 3.73,                           # float | None: Shannon entropy score
    "fingerprint": "...",                      # str: deterministic fingerprint
    "metadata": {                              # dict: raw metadata preserved for backend
        "rule_id": "aws-access-key-id",
        "description": "AWS Access Key ID",
        "entropy": 3.73,
        "tags": []
    }
}
```

### 5.2 Severity Mapping by Secret Type
- **`CRITICAL`:** Cloud Provider Root/IAM keys (AWS, GCP, Azure), Private Cryptographic Keys (RSA, EC, PGP).
- **`HIGH`:** SaaS & Platform API Tokens (GitHub PAT, Stripe, Slack Webhook, OpenAI).
- **`MEDIUM`:** Generic passwords, connection strings with generic credentials, high-entropy tokens without specific provider prefixes.

---

## 6. Gitleaks Exit Codes & Execution Status Matrix

Gitleaks uses exit code conventions similar to Bandit:
- **`0`:** Scan completed successfully with **0 leaks detected**.
- **`1`:** Scan completed successfully with **leaks detected** (findings present).
- **`>= 2`:** Execution error (bad flags, unreadable path, fatal failure).

`SecretsScanner` interprets exit codes 0 and 1 with valid JSON as successful scans:

| Subprocess Outcome | Output Valid? | Status | Findings State | Error Field |
|---|---|---|---|---|
| Exit code 0, zero leaks | Valid JSON (`[]`) | `success` | `[]` | `None` |
| Exit code 1, leaks found | Valid JSON list | `success` | Parsed list of redacted raw findings (>= 1) | `None` |
| Exit code >= 2, no output | No / Invalid JSON | `failed` | `[]` | Sanitized stderr summary |
| Missing binary (`FileNotFoundError`) | N/A | `failed` (or `skipped` if configured) | `[]` | `"Gitleaks executable not found: 'gitleaks'"` |
| Subprocess timeout (`TimeoutError`) | N/A | `failed` | `[]` | `"Gitleaks execution timed out after 60.0 seconds"` |
| Workspace missing or non-directory | N/A | `skipped` (missing) / `failed` (file) | `[]` | Clean diagnostic message |
| Workspace empty (0 files) | N/A | `skipped` | `[]` | `None` |

---

## 7. Backward Compatibility & Interface Compliance

- `SecretsScanner` inherits from `BaseScanner` and implements `name = "secrets"` and `async def scan(workspace: str) -> ScannerExecutionResult`.
- Zero changes are made to Dev B's schemas, database models, or FastAPI routers.
- The scanner operates fully self-contained and mock-testable without requiring a real Gitleaks binary in test environments.
