# Service Interfaces Specification — Dev C (Cybersecurity & Scanner Modules)

- **Document:** `docs/SERVICE_INTERFACES_DEV_C.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator:** Dev B (Backend Developer)
- **Status:** Final Approved & Implemented Interface Specification (Phase 6)
- **Version:** 2.0.0

---

## 1. Executive Summary & Purpose

This document defines the formal, implemented architectural contracts between the **scanner modules and DevOps infrastructure** (authored and maintained by Dev C) and the **backend scan orchestration, persistence, and reporting services** (owned by Dev B).

Adherence to this contract guarantees:
1. **Loose Coupling:** The backend orchestrator treats all scanners uniformly via the `BaseScanner` abstraction without coupling to tool-specific CLI invocations.
2. **Defensive Error Handling:** Individual scanner crashes, non-zero exits, or timeouts do not disrupt other scanner executions or fail the scan job.
3. **Strict AI Boundaries:** External AI integration receives only sanitized, redacted finding summaries, never raw repositories, source trees, or credentials.
4. **Clean Ownership:** Strict division of responsibilities ensures Dev C owns scanner adapters, custom rules, normalization, archive defenses, and container security, while Dev B owns scan persistence, database models, upload routes, and reporting presentation.

---

## 2. Common Scanner Interface Contract (`BaseScanner`)

All scanner adapters in `backend/app/scanners/` inherit from the abstract base class `BaseScanner` (`backend/app/scanners/base_scanner.py`):

```python
from abc import ABC, abstractmethod
from typing import Any, Literal
from pydantic import BaseModel, Field

class BaseScanner(ABC):
    """Abstract base class for all Thread Trace security scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier of the scanner (e.g., 'semgrep', 'bandit')."""
        raise NotImplementedError

    @property
    def scanner_name(self) -> str:
        """Alias for name property."""
        return self.name

    @abstractmethod
    async def scan(self, workspace: str) -> ScannerExecutionResult:
        """
        Execute static analysis scan against an isolated workspace directory.

        Args:
            workspace: Absolute path to the isolated directory containing extracted source code.

        Returns:
            ScannerExecutionResult: Structured result containing raw findings, status, duration, and error.
        """
        raise NotImplementedError
```

---

## 3. Scanner Execution Result Contract (`ScannerExecutionResult`)

Every scanner adapter returns a typed `ScannerExecutionResult`:

```python
class ScannerExecutionResult(BaseModel):
    """Structured result model returned by every scanner execution."""
    scanner_name: str = Field(..., min_length=1, description="Unique identifier of the scanner")
    status: Literal["success", "partial", "failed", "skipped"] = Field(..., description="Execution status")
    findings: list[dict[str, Any]] = Field(default_factory=list, description="Raw finding dictionaries")
    duration_seconds: float = Field(default=0.0, ge=0.0, description="Execution duration in seconds")
    error: str | None = Field(default=None, description="Safe error description if partial or failed")
```

### Invariants:
- `scanner_name`: Must be one of `"semgrep"`, `"bandit"`, `"secrets"`, `"dependency"`, `"custom-rules"`.
- `status`: One of `"success"`, `"partial"`, `"failed"`, `"skipped"`.
- `findings`: A list of dictionaries, each formatted to translate directly into the canonical `Finding` model via `normalize_raw_finding()`.
- `duration_seconds`: Real elapsed wall-clock time in seconds.
- `error`: Safe, bounded string describing errors if `status` is `"partial"` or `"failed"`.

---

## 4. Individual Scanner Adapters

Thread Trace integrates five distinct static analysis modules:

| Scanner Adapter | Implementation File | Engine Binary / CLI | Constructor Signature | Execution Scope |
|---|---|---|---|---|
| **SemgrepScanner** | `backend/app/scanners/semgrep_scanner.py` | `semgrep --json` | `__init__(timeout_seconds=60, custom_rules_dir=None)` | Polyglot AST pattern matching, OWASP Top 10 rules. |
| **BanditScanner** | `backend/app/scanners/bandit_scanner.py` | `bandit -f json` | `__init__(timeout_seconds=60, profile=None)` | Python-specific AST security linting. |
| **SecretsScanner** | `backend/app/scanners/secrets_scanner.py` | `gitleaks dir` | `__init__(timeout_seconds=60, config_path=None)` | High-entropy secret and token detection. |
| **DependencyScanner** | `backend/app/scanners/dependency_scanner.py` | `osv-scanner --json` | `__init__(timeout_seconds=60, lockfile_only=False)` | Known CVE and GHSA advisory matching against manifests. |
| **CustomRulesScanner** | `backend/app/scanners/custom_rules/scanner.py` | In-process Python AST | `__init__(registry=None, timeout=60)` | Modular proprietary AST and regex rule packs. |

---

## 5. Custom Rules Architecture

The Custom Rules engine (`backend/app/scanners/custom_rules/`) provides targeted in-house detection:
- **Base Class (`BaseCustomRule`):** Defines `rule_id`, `domain`, `severity`, `confidence`, `title`, and `evaluate(file_path, content, ast_tree)`.
- **Modular Packs:**
  - `custom.secrets.*`: Hardcoded API keys, JWT secrets, database connection passwords.
  - `custom.web.*`: SQL injection, command injection, path traversal, unsafe deserialization.
  - `custom.network.*`: Disabled TLS verification, cleartext HTTP endpoints.
  - `custom.auth.*`: Weak password hashing algorithms, hardcoded authentication tokens.
  - `custom.config.*`: Production debug flags, permissive CORS wildcards, unpinned dependencies.
- **Rule Registry:** Dynamic registration via `register_all_custom_rules(default_registry)`.

---

## 6. Finding Normalization Engine (`Finding`)

Disparate scanner outputs are translated into Dev B's canonical `Finding` Pydantic model (`backend/app/schemas/finding.py`):

```python
class Finding(BaseModel):
    id: str                                                  # find_<uuid4_hex>
    domain: str                                              # Canonical or display domain
    rule_id: str                                             # Prefixed rule ID (e.g. bandit.B608)
    title: str                                               # Vulnerability title (<=200 chars)
    severity: Literal["critical", "high", "medium", "low"]  # Normalized severity
    file: str                                                # Workspace-relative POSIX path (/)
    line: int | None = None                                  # 1-indexed line or None
    evidence: str                                            # Redacted snippet (<=1000 chars)
    confidence: str                                          # "high", "medium", "low"
    explanation: str | None = None                           # Enriched asynchronously by AI
    recommendation: str | None = None                        # Enriched asynchronously by AI
    tool: str                                                # Scanner engine identifier
    raw_category: str | None = None                          # Original tool category
```

---

## 7. Two-Tier Domain Taxonomy Mapping

Thread Trace defines two distinct domain layers:
1. **User-Facing Display Taxonomy (5 Project-Level Domains):**
   - Secrets & Sensitive Information Management
   - Web Application Security
   - Network & Communication Security
   - Authentication & Access Control
   - Dependency & Configuration Security
2. **Canonical Backend Identifiers (10 Normalized Categories):**
   - `secrets`
   - `injection`, `input_validation`, `other`
   - `cryptography`, `logging`
   - `authentication`, `authorization`
   - `dependencies`, `configuration`

---

## 8. Timeout, Execution & Resource Limits

| Resource Parameter | Implemented Value | Enforcement Mechanism |
|---|---|---|
| **Per-Scanner Timeout** | 60 seconds (`SCANNER_TIMEOUT_SECONDS`) | Subprocess async timeout / `asyncio.wait_for()` |
| **Global Scan Timeout** | 300 seconds (`GLOBAL_SCAN_TIMEOUT_SECONDS`) | Orchestrator job timeout |
| **Container Memory** | 2,048 MB (`mem_limit: 2048m`) | Docker cgroups v2 |
| **Container CPUs** | 2.0 CPUs (`cpus: 2.0`) | Docker cgroups v2 |
| **Container PIDs** | 150 (`pids_limit: 150`) | Docker cgroups v2 |
| **Evidence Character Cap** | 1,000 characters | Normalizer `bound_evidence()` |
| **Max Stdout Buffer** | 10 MB (`SCANNER_MAX_OUTPUT_BYTES`) | Async subprocess stream reader |

---

## 9. Scanner Failure Semantics & Isolation

- **`safe_scan()` Decorator:** Wraps every scanner execution. Catches `CalledProcessError`, `TimeoutExpired`, `FileNotFoundError`, and `JSONDecodeError`.
- **Status Matrix (`aggregate_scanner_statuses`):**
  - All scanners succeed -> `"success"`
  - Any scanner succeeds, at least one fails -> `"partial"`
  - All scanners fail -> `"failed"`
  - All scanners skipped (e.g. no matching language files) -> `"skipped"`
- **Non-Termination:** A failure in one scanner (e.g. Bandit crashing on Python 2 syntax) **never** terminates other running scanners or drops their findings.

---

## 10. Secret Redaction Boundary

The `RedactionEngine` (`app/core/security.py`) sanitizes findings before exposure to APIs or AI:
- High-entropy AWS access keys (`AKIA...`) -> `[REDACTED_AWS_KEY]`
- GitHub tokens (`ghp_...`, `github_pat_...`) -> `[REDACTED_GITHUB_TOKEN]`
- Database connection strings (`mongodb://user:pass@host`) -> `mongodb://user:[REDACTED]@host`
- Multiline RSA/EC private keys (`-----BEGIN PRIVATE KEY-----...`) -> `[REDACTED_PRIVATE_KEY]`
- Evidence snippets are bounded to at most 1,000 characters with trailing ellipsis.

---

## 11. AI Context Boundary & Sanitization Contract

To prevent training data leakage or intellectual property exposure:
1. **Strictly Forbidden:** Raw source files, whole repository ZIP archives, internal database URIs, and unmasked credentials must **never** be sent to AI providers.
2. **Permitted AI Payload:** Only normalized, evidence-bounded `Finding` objects are passed to `ai_service.py`.
3. **Additive Enrichment:** AI outputs populate only `finding.explanation` and `finding.recommendation`. AI models cannot alter verified scanner coordinates, severity, or rule IDs.

---

## 12. Workspace & Container Security Assumptions

- **Non-Root Execution:** Scanner worker container runs strictly as UID 10001 (`scanner`).
- **Filesystem Security:**
  - Root filesystem is mounted read-only (`read_only: true`).
  - Extracted source code is mounted strictly read-only (`:ro`).
  - Only `/tmp` (tmpfs 64MB) and the workspace output directory are writable.
- **Network Isolation:** Scanner container is connected solely to `scanner-net` configured with `internal: true` (no internet gateway, completely isolated from MongoDB `db-net`).
- **No Docker Socket:** `docker.sock` is never mounted into the scanner container.

---

## 13. Dev B Integration Responsibilities

Dev B consumes the scanner interface as follows:
1. **Archive Ingestion:** Validates uploads against `validate_zip_archive_security()` before extraction.
2. **Workspace Creation:** Creates workspaces using `WorkspaceManager.create_workspace(scan_id)`.
3. **Extraction:** Extracts files strictly into `<workspace>/source/`.
4. **Invocation:** Calls `run_scanners(workspace_source_dir, selected_scanners)` or invokes the worker container CLI.
5. **Report Ingestion:** Reads the consolidated JSON payload from `process_and_normalize_results()`, persists findings in MongoDB, and triggers AI enrichment if requested.
6. **Workspace Cleanup:** Calls `WorkspaceManager.cleanup_workspace(scan_id)` in a `finally` block.

---

## 14. Scanner Limitations & Operational Guidance

- **SAST Scope:** Detections are based on static pattern matching and AST traversal. They cannot prove exploitability or replace human penetration testing.
- **Supported Languages:** Python, JS/TS, Go, Java, Ruby, C/C++, Dockerfiles, YAML, JSON, manifest files.
- **Unsupported:** Compiled binaries (`.exe`, `.so`), encrypted archives, and media assets.
- **Manual Assessment:** Critical authentication flows and low-confidence findings require manual review.
