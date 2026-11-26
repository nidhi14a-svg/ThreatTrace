# Scanner Output Specification: Parser & Error Boundaries

**File:** `specs/SCANNER_OUTPUT_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Targets:** `backend/app/scanners/base_scanner.py`, `backend/app/scanners/`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 2, Task 2.6)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

This specification establishes the standardized **Parser Boundaries**, **Evidence Retention Rules**, and **Error Confinement Policies** across all scanner integrations within Thread Trace (Semgrep, Bandit, Gitleaks, OSV-Scanner, and future Custom Security Rules).

The primary objective is to guarantee that:
1. Every scanner adapter parses raw tool output deterministically and yields raw finding dictionaries conforming to the `ScannerExecutionResult.findings` contract.
2. Raw evidence is safely captured, strictly bounded in length, and scrubbed of sensitive credentials before storage.
3. Scanner errors (timeouts, missing binaries, malformed output, process crashes) are captured safely within the scanner's own result object without crashing other scanners or the backend orchestration workflow.
4. **AI Context Boundary Enforced:** External AI services (e.g., Gemini / Anthropic / OpenAI) never receive unsanitized source repositories, process memory dumps, or raw credentials. Downstream AI processing receives only bounded, sanitized finding-level metadata.

---

## 2. Standardized Raw Finding Output Contract

Every scanner adapter returns a `ScannerExecutionResult` whose `findings` attribute is a `list[dict[str, Any]]`. Every raw finding dictionary produced across all tools must adhere to the following schema:

| Field Name | Type | Required? | Boundary Constraint / Format |
|---|---|:---:|---|
| `scanner_name` | `str` | YES | Identifier of the tool: `"semgrep"`, `"bandit"`, `"secrets"`, `"dependency"`, `"custom-rules"`. |
| `rule_id` | `str` | YES | Unique rule/check ID: e.g. `semgrep.xss`, `bandit.B608`, `gitleaks.aws-access-key-id`, `GHSA-...`. |
| `title` | `str` | YES | Human-readable finding summary, max 200 characters, no raw secrets or control characters. |
| `severity` | `str` | YES | Normalized tier: strictly `"critical"`, `"high"`, `"medium"`, or `"low"`. |
| `file` | `str` | YES | Workspace-relative POSIX path with forward slashes (`/`), never leading `/`, never `../`. |
| `line` | `int \| None` | YES | 1-indexed positive integer (`>= 1`), or `None` for manifest-level / project-wide findings. |
| `evidence` | `str` | YES | Redacted code snippet or synthetic description, bounded to max 1,000 characters. |
| `confidence` | `str` | YES | Normalized confidence level: strictly `"high"`, `"medium"`, or `"low"`. |
| `raw_category` | `str` | YES | Scanner-native category or taxonomy mapping (e.g., `"sql_injection"`, `"hardcoded_secret"`). |

### 2.1 Scanner-Specific Supplemental Metadata
Scanners may include non-breaking supplemental metadata to assist Dev B's backend normalization or AI enrichment:
- **Bandit:** `line_range: list[int]`, `cwe_id: int | None`, `test_name: str`.
- **Semgrep:** `start_col: int`, `end_col: int`, `metadata: dict`.
- **Gitleaks:** `secret_type: str`, `entropy: float`.
- **OSV-Scanner:** `package_name: str`, `package_version: str`, `package_ecosystem: str`, `aliases: list[str]`, `fixed_versions: list[str]`, `advisory_url: str`.

---

## 3. Tool-Specific Parser Boundaries

```
+-----------------------------------------------------------------------------------+
|                            Raw CLI Subprocess Output                              |
+-----------------------------------------------------------------------------------+
         |                           |                         |
         v                           v                         v
+------------------+       +-------------------+     +--------------------+
|  Semgrep JSON    |       |   Bandit JSON     |     |   Gitleaks JSON    | ... OSV-Scanner
+------------------+       +-------------------+     +--------------------+
         |                           |                         |
         +---------------------------+-------------------------+
                                     |
                                     v
                       [ Parser & Sanitizer Boundary ]
                                     |
                       - Max Buffer: 10 MB
                       - JSON Extraction (ignore CLI banners)
                       - Mandatory Credential Redaction
                       - Max Evidence Length: 1,000 chars
                       - Workspace Path Normalization & Traversal Rejection
                                     |
                                     v
                       [ ScannerExecutionResult ]
                       status: success | partial | failed | skipped
                       findings: list[dict[str, Any]] (Sanitized)
```

### 3.1 Semgrep Parser Boundary
- **Input Format:** CLI stdout in JSON format (`--json`, `--metrics=off`, `--disable-version-check`).
- **Extraction Logic:**
  - Root: object containing `"results"` array and optional `"errors"` array.
  - Path: `item["path"]` -> normalized relative to workspace root.
  - Rule: `item["check_id"]`.
  - Line: `item["start"]["line"]`.
  - Evidence: `item["extra"]["lines"]` (first 1,000 chars, stripped of trailing newlines).
  - Severity: mapped from `item["extra"]["severity"]` (`ERROR` -> `high`/`critical`, `WARNING` -> `medium`, `INFO` -> `low`).
  - Confidence: derived from `item["extra"]["metadata"]["confidence"]` (default `"high"`).
- **Error Tolerance:** If `errors` array is present in JSON output, status is marked as `partial` with findings preserved.

### 3.2 Bandit Parser Boundary
- **Input Format:** CLI stdout in JSON format (`-f json -q`).
- **Extraction Logic:**
  - Root: object containing `"results"` array and `"errors"` array.
  - Path: `item["filename"]` -> normalized relative to workspace root.
  - Rule: `bandit.<item["test_id"]>`.
  - Line: `item["line_number"]`.
  - Evidence: `item["code"]` (bounded to 1,000 chars).
  - Severity: mapped from `item["issue_severity"]` (`HIGH` -> `high`, `MEDIUM` -> `medium`, `LOW` -> `low`).
  - Confidence: mapped from `item["issue_confidence"]`.
- **Exit Code Semantics:** Exit code `1` denotes findings present, parsed as `success`. Exit code `>= 2` denotes fatal runtime errors.

### 3.3 Secrets Scanner (Gitleaks) Parser Boundary
- **Input Format:** Ephemeral file report (`--report-format json`, `--redact`).
- **Extraction Logic:**
  - Root: JSON array of leak finding objects.
  - Path: `item["File"]` -> normalized relative to workspace root.
  - Rule: `item["RuleID"]`.
  - Line: `item["StartLine"]`.
  - Evidence: `item["Match"]` (mandatory in-memory regex redaction applied before storage).
  - Severity: mapped by rule sensitivity (cloud credentials & private keys -> `critical`, SaaS tokens -> `high`, generic credentials -> `medium`).
  - Confidence: `"high"` for format/entropy matches.
- **Redaction Mandate:** Raw matched secret (`item["Secret"]`) is NEVER retained. If `--redact` fails or is absent, the in-memory redaction filter replaces sensitive tokens with `[REDACTED]`.

### 3.4 Dependency Scanner (OSV-Scanner) Parser Boundary
- **Input Format:** CLI stdout in JSON format (`--json -r <workspace>`).
- **Extraction Logic:**
  - Root: object containing `"results"` array.
  - Path: `item["source"]["path"]` -> sanitized relative to workspace root.
  - Rule: `vuln["id"]` (GHSA or CVE identifier).
  - Line: `None` (dependency advisories apply at the manifest level).
  - Evidence: synthesized string: `"Dependency '<pkg>' version '<ver>' in '<file>' matches advisory '<id>' (<summary>). Fixed in: <fixed_versions>"` (max 1,000 chars).
  - Severity: derived from CVSS v3 score / vector or `database_specific.severity`.
  - Confidence: `"high"` for lockfiles (`package-lock.json`, `poetry.lock`, etc.), `"medium"` for unpinned manifests (`requirements.txt`, etc.).
- **Exit Code Semantics:** Exit code `1` denotes vulnerabilities present, parsed as `success`.

---

## 4. Evidence Retention & Redaction Boundaries

### 4.1 Bounding Constraints
To protect against unbounded memory consumption and database bloat:
1. **Evidence Length Limit:** Maximum 1,000 characters per finding. Any evidence exceeding this limit must be truncated with a trailing ellipsis (`...`).
2. **Buffer Output Limit:** Subprocess stdout and stderr streams are capped at `max_output_bytes` (default 10 MB). Output beyond this limit is truncated.
3. **No File Dump Invariant:** Scanner adapters are strictly prohibited from storing entire source files, full AST dumps, or multi-kilobyte code blocks in finding dictionaries.

### 4.2 In-Memory Credential Redaction Invariant
All evidence context—regardless of tool—must pass through in-memory credential sanitization before assignment to `finding["evidence"]`:
- **AWS Access Keys:** `AKIA[0-9A-Z]{16}` -> `AKIA****************`
- **GitHub PATs:** `ghp_[0-9a-zA-Z]{36}` -> `ghp_************************************`
- **Private Keys:** `-----BEGIN [A-Z ]+ PRIVATE KEY-----...` -> `[REDACTED_PRIVATE_KEY]`
- **Slack Webhooks:** `https://hooks.slack.com/services/...` -> `https://hooks.slack.com/services/[REDACTED]`
- **Generic Bearer Tokens:** `Bearer [a-zA-Z0-9_\-\.]{20,}` -> `Bearer [REDACTED]`

---

## 5. Path Traversal & Filesystem Sanitization Boundaries

Findings reference target files using the `file` field. To prevent directory traversal attacks or internal host path exposure:
1. **Workspace Root Anchoring:** Every file path must resolve within the workspace directory:
   ```python
   rel_path = resolved_path.relative_to(workspace_resolved_path).as_posix()
   ```
2. **Traversal Rejection:** If a file path attempts to traverse parent directories (`../`) or resolves outside `workspace_path`:
   - It is immediately replaced with `"[REJECTED_OUTSIDE_WORKSPACE]"`.
   - It must never expose host root paths (e.g., `/etc/passwd`, `C:\Windows\System32`).
3. **Posix Formatting:** All paths must use forward slashes (`/`), without leading `./` or leading `/`.

---

## 6. Error Confinement & Fault Isolation Boundaries

### 6.1 Subprocess Timeout Boundary
- Every scanner subprocess execution is wrapped in `asyncio.wait_for(proc.communicate(), timeout=self.timeout_seconds)`.
- If execution exceeds the timeout:
  1. The process is terminated immediately (`proc.kill()`).
  2. The scanner returns `status="failed"`.
  3. `error="<Scanner> execution timed out after <N> seconds."`.
  4. Duration is recorded accurately.
  5. No exception is leaked to the orchestrator.

### 6.2 Missing Dependency Boundary
- If the tool binary is not present on `PATH`:
  - Default behavior: returns `status="failed"` with a clear diagnostic message.
  - If `allow_skip_if_missing=True`: returns `status="skipped"`, `findings=[]`, `error=None`.
- The failure of one binary (e.g., OSV-Scanner missing) must NOT prevent Semgrep, Bandit, or Gitleaks from executing.

### 6.3 Malformed Output Boundary
- If a scanner produces non-JSON output, corrupted JSON, or truncated text:
  1. The scanner attempts regex extraction of the JSON payload between the first `{` or `[` and the last `}` or `]`.
  2. If decoding still fails:
     - If the returncode was non-zero: returns `status="failed"` with sanitized stderr (max 1,000 chars).
     - If the returncode was 0: returns `status="failed"` with `"Malformed scanner JSON output."`.
  3. No unhandled `json.JSONDecodeError` propagates out of `scan()`.

---

## 7. External AI Context Boundary (Anti-Leak Policy)

External LLM integrations (managed by Dev B in `backend/app/ai/`) generate explanations and remediation advice for detected vulnerabilities. To safeguard intellectual property and comply with cybersecurity standards:

1. **Repository Boundary:**
   - Scanner classes must **never** call AI endpoints.
   - Entire repositories or unflagged source code files must **never** be sent to an AI service.
2. **Finding-Only Context:**
   - Downstream AI prompts must receive only the normalized finding fields:
     - `rule_id`
     - `title`
     - `severity`
     - `file`
     - `line`
     - `evidence` (already redacted and bounded to <= 1,000 chars)
     - `confidence`
3. **Evidence Immutability:**
   - AI responses (`explanation`, `recommendation`) are separate fields and must **never** overwrite or alter the verified `evidence`, `file`, `line`, or `rule_id` fields.

---

## 8. Summary Table of Scanner Parser Boundaries

| Scanner | Input Source | Primary Parsing Target | Output Exit Code Meaning | Evidence Source | Evidence Redaction |
|---|---|---|---|---|---|
| **Semgrep** | stdout (JSON) | `results[]` | 0: clean/findings, 1: error/findings | `extra.lines` | In-memory redaction |
| **Bandit** | stdout (JSON) | `results[]` | 0: clean, 1: findings, >=2: fatal | `code` | In-memory redaction |
| **Gitleaks** | Temp file (JSON) | Root array `[]` | 0: clean, 1: leaks, >=2: error | `Match` | `--redact` + In-memory |
| **OSV-Scanner** | stdout (JSON) | `results[].packages[].vulnerabilities[]` | 0: clean, 1: vulns, >=2: error | Synthetic string | In-memory bounded |
| **Custom Rules** | In-memory AST/Regex | Match objects | 0: clean, 1: findings | Source snippet | In-memory redaction |
