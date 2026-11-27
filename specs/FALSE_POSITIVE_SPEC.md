# False Positive Management & Deduplication Specification

**File:** `specs/FALSE_POSITIVE_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Targets:** `backend/app/scanners/suppression.py`, `backend/tests/test_suppression.py`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 3, Task 3.8)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

In automated application security testing, high false-positive rates erode developer trust. Concurrently, running multiple overlapping static analysis engines produces duplicate reports for identical security flaws.

This specification establishes Thread Trace's **False Positive Management & Deduplication Engine**:
1. **Deterministic Deduplication:** Merging duplicate findings across disparate scanners while preserving provenance.
2. **Auditable Suppression & Allowlisting:** Explicit, traceable suppression by rule ID, file glob, or inline code comment.
3. **Critical Severity Guardrails:** Prohibiting silent suppression of `critical` vulnerabilities without explicit rationale.
4. **Confidence Calibration:** Maintaining low-confidence findings visibly while allowing filtered dashboard views rather than silent drop.

---

## 2. Duplicate Detection & Precedence Hierarchy

### 2.1 Deduplication Fingerprint
Two findings are classified as duplicates if they share:
`fingerprint = (finding.file, finding.line, finding.domain)`

*(Note: For manifest-level dependency findings where `line is None`, the fingerprint is `(finding.file, finding.rule_id)`).*

### 2.2 Tool Precedence Hierarchy
When duplicate findings are detected, the authoritative finding is selected according to tool specialization:

```
[ Specialized Engine ] > [ Semgrep Polyglot ] > [ Custom Rules ]
 (Gitleaks, Bandit,
   OSV-Scanner)
```

1. **Secrets:** Gitleaks > Semgrep > Custom Rules
2. **Python Flaws:** Bandit > Semgrep > Custom Rules
3. **Dependencies:** OSV-Scanner > Custom Rules
4. **Web / Polyglot:** Semgrep > Custom Rules

The non-authoritative duplicate is recorded in the suppression audit trail with reason `"duplicate_of_<authoritative_id>"`.

---

## 3. Suppression & Allowlisting Mechanisms

### 3.1 Allowlist Configuration Schema
```python
class SuppressionRule(BaseModel):
    rule_id: str | None = None          # Specific rule ID to suppress (e.g. 'bandit.B101')
    file_pattern: str | None = None     # Glob pattern (e.g. 'tests/**', 'docs/**')
    reason: str                         # Mandatory audit justification
    allow_critical: bool = False        # Must be True to suppress critical severity
```

### 3.2 Guardrails Against Blind Suppression
1. **No Silent Drops:** Low-confidence findings are **never** discarded automatically. They are labeled `confidence: "low"` and remain triageable.
2. **Critical Vulnerability Shield:** Any attempt to suppress a `critical` severity finding without `allow_critical=True` is rejected.
3. **Audit Trail:** Every suppressed finding is returned in an `audit_log` with the matching rule, reason, and timestamp.

---

## 4. Suppression Engine Implementation (`suppression.py`)

The suppression engine provides two primary operations:
1. `deduplicate_findings(findings: list[Finding]) -> tuple[list[Finding], list[dict]]`
2. `apply_suppressions(findings: list[Finding], rules: list[SuppressionRule]) -> tuple[list[Finding], list[dict]]`
