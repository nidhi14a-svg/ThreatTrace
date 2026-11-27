# Scanner Report Mapping Specification

**File:** `specs/SCANNER_REPORT_MAPPING_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Collaborator:** Dev B — Scan Orchestration & Reporting Service  
**Implementation Targets:** `backend/app/scanners/normalizer.py`, `backend/app/scanners/worker_runner.py`, `backend/app/scanners/suppression.py`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 6, Task 6.3)  
**Status:** APPROVED & IMPLEMENTED  

---

## 1. Overview & Objectives

Thread Trace separates static analysis data collection from report presentation:
- **Dev C's Scanner Modules:** Discover, extract, normalize, deduplicate, and redact raw security findings. They emit a structured, canonical scan payload containing normalized `Finding` objects and per-tool execution metadata.
- **Dev B's Reporting Service:** Consumes the normalized scan payload, associates findings with persistent scan jobs in MongoDB, aggregates severity and domain counts, triggers optional AI remediation enrichment, and formats API and export representations (JSON/PDF).

This specification formalizes the **data contract and mapping rules** between Dev C's scanner output and Dev B's reporting engine.

---

## 2. Two-Tier Domain Taxonomy Mapping

Thread Trace defines two distinct domain representations:
1. **User-Facing Display Domains (5 Project-Level Categories):** Used in dashboards, executive summaries, and top-level filter tabs.
2. **Canonical Backend Domain Identifiers (10 Normalized Categories):** Used in MongoDB indexes, finding schema validation, and targeted query filtering.

### 2.1 Bidirectional Mapping Matrix

| Display Domain (5 Categories) | Backend Domain Identifiers (10 Identifiers) | Scope & Focus |
|---|---|---|
| **Secrets & Sensitive Information Management** | `secrets` | Hardcoded keys, tokens, private keys, connection strings. |
| **Web Application Security** | `injection`<br>`input_validation`<br>`other` | SQLi, command injection, XSS, SSRF, path traversal, deserialization. |
| **Network & Communication Security** | `cryptography`<br>`logging` | Cleartext HTTP, disabled TLS verification, weak ciphers, leaked logs. |
| **Authentication & Access Control** | `authentication`<br>`authorization` | Broken authentication, weak password hashing, missing route guards. |
| **Dependency & Configuration Security** | `dependencies`<br>`configuration` | Known CVEs/GHSAs, unpinned packages, debug mode, wildcard CORS. |

Dev B's reporting service uses this mapping to compute high-level dashboard summaries from granular finding records.

---

## 3. Normalized Finding Aggregation Payload

Dev C's scanner runner emits the following consolidated structure (`process_and_normalize_results`):

```json
{
  "status": "success",
  "duration_seconds": 1.45,
  "scanners_executed": ["semgrep", "bandit", "secrets", "dependency", "custom_rules"],
  "scanner_results": {
    "semgrep": {
      "scanner_name": "semgrep",
      "status": "success",
      "findings_count": 4,
      "duration_seconds": 0.52,
      "error": null
    },
    "bandit": {
      "scanner_name": "bandit",
      "status": "success",
      "findings_count": 2,
      "duration_seconds": 0.28,
      "error": null
    },
    "secrets": {
      "scanner_name": "secrets",
      "status": "success",
      "findings_count": 1,
      "duration_seconds": 0.15,
      "error": null
    },
    "dependency": {
      "scanner_name": "dependency",
      "status": "success",
      "findings_count": 3,
      "duration_seconds": 0.35,
      "error": null
    },
    "custom_rules": {
      "scanner_name": "custom_rules",
      "status": "success",
      "findings_count": 5,
      "duration_seconds": 0.15,
      "error": null
    }
  },
  "total_findings": 12,
  "deduplicated_count": 3,
  "suppressed_count": 0,
  "findings": [
    {
      "id": "find_7a2b9c1d",
      "domain": "Web Application Security",
      "rule_id": "semgrep.python.sqli",
      "title": "SQL Injection via Untrusted Query Construction",
      "severity": "high",
      "file": "app/routes.py",
      "line": 42,
      "evidence": "db.execute(f'SELECT * FROM users WHERE name = {user}')",
      "confidence": "high",
      "explanation": null,
      "recommendation": null,
      "tool": "semgrep",
      "raw_category": "security/injection"
    }
  ]
}
```

---

## 4. Severity & Domain Metric Aggregation Rules

When Dev B processes the scanner payload for the dashboard report:

### 4.1 Severity Summary
Count findings across the 4 canonical tiers:
- `critical_count = count(findings where severity == "critical")`
- `high_count = count(findings where severity == "high")`
- `medium_count = count(findings where severity == "medium")`
- `low_count = count(findings where severity == "low")`
- Total: `total_findings = critical + high + medium + low`

### 4.2 Status Aggregation Matrix
- **`success`:** All invoked scanners completed without fatal crashes or timeouts.
- **`partial`:** At least one scanner succeeded or skipped, and at least one scanner failed. Available findings from successful scanners are preserved.
- **`failed`:** All scanners encountered unhandled crashes or missing binaries.
- **`skipped`:** Workspace contained no scan targets (e.g. empty directory).

### 4.3 Deduplication Priority Rules
Overlapping findings at the same file and line coordinate are resolved according to `TOOL_PRIORITY`:
1. `gitleaks` (Priority 10) — Authoritative for secret detections.
2. `bandit` (Priority 9) — Authoritative for Python AST flaws.
3. `osv-scanner` (Priority 8) — Authoritative for dependency advisories.
4. `semgrep` (Priority 7) — Authoritative for polyglot/complex taint rules.
5. `custom-rules` (Priority 5) — Specialized in-house checks.

Deduplicated items are logged with an audit trail linking the suppressed duplicate finding ID to the authoritative finding ID.

---

## 5. Architectural Boundaries

1. **Scanner modules must NOT implement HTML/PDF rendering:** Output from `worker_runner.py` is strictly JSON.
2. **Scanner modules must NOT dictate HTTP API schemas:** Routes in `backend/app/api/routes/reports.py` and `scans.py` are owned by Dev B.
3. **Immutability of Findings:** Once generated, `Finding.id`, `rule_id`, `tool`, `file`, `line`, and `evidence` must remain immutable across persistence and reporting.
