# False-Positive Validation Specification

- **Document:** `specs/FALSE_POSITIVE_VALIDATION_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target File:** `backend/tests/test_false_positive_validation.py`
- **Status:** Approved Specification (Phase 5, Task 5.7)
- **Version:** 1.0.0

---

## 1. Objectives & Comparative Testing

Evaluates scanner behavior across synthetic vulnerable versus clean codebases to guarantee high precision, low false-positive rates, and deterministic deduplication.

### Key Validation Checks:
1. **Clean Fixture Baseline:** Representative clean projects must yield zero findings for critical and high severity rules.
2. **Deduplication Priority:** Overlapping findings from multiple tools on identical file coordinates are merged, preserving the authoritative scanner.
3. **Suppression Guardrails:** Critical severity findings cannot be suppressed without explicit `allow_critical=True` audit approval.
4. **Confidence Classifications:** Low confidence findings do not escalate to high severity.
