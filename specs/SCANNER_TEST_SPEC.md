# Scanner Test Specification

- **Document:** `specs/SCANNER_TEST_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target File:** `backend/tests/test_scanner_fixtures.py`
- **Status:** Approved Specification (Phase 5, Task 5.3)
- **Version:** 1.0.0

---

## 1. Test Verification Strategy

The scanner test suite verifies end-to-end detection, normalization, coordinate mapping, and evidence redaction across all five detection engines:

1. **Semgrep:** AST pattern matching on web and injection patterns.
2. **Bandit:** Python AST vulnerability checks (e.g., `B602`, `B501`, `B303`, `B307`).
3. **Gitleaks:** High-entropy secret and token pattern detection.
4. **OSV-Scanner:** Lockfile and manifest dependency advisory mapping.
5. **Custom Rules:** In-tree AST and regex rule validation across all five domains.

---

## 2. Assertions & Validation Criteria

Each scanner test against vulnerable fixtures must assert:
- `ScannerExecutionResult.status` is `success` or `partial`.
- `findings` list contains expected rule IDs.
- Normalized finding attributes conform to `Finding` schema:
  - `id`: Non-empty string.
  - `domain`: Valid canonical domain string.
  - `severity`: One of `critical`, `high`, `medium`, `low`.
  - `confidence`: One of `high`, `medium`, `low`.
  - `file`: Workspace-relative normalized forward-slash path.
  - `line`: Optional integer >= 1 or `None`.
  - `evidence`: Bounded to 1000 characters and free of unmasked secrets.
