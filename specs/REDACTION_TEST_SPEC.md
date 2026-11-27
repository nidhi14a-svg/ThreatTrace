# Redaction Test Specification

- **Document:** `specs/REDACTION_TEST_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target File:** `backend/tests/test_secret_redaction_verification.py`
- **Status:** Approved Specification (Phase 5, Task 5.5)
- **Version:** 1.0.0

---

## 1. Objectives & Threat Mitigation

Ensures discovered credentials, passwords, tokens, and private keys never leak into logs, scan reports, database records, or third-party AI context prompts.

### Test Scenarios:
1. **Structured Token Masking:** AWS access keys (`AKIA...`), GitHub PATs (`ghp_...`), Slack tokens (`xoxb-...`), Stripe live keys (`sk_live_...`). Formats retain identifying prefix while body is masked with asterisks.
2. **Unstructured Credential Masking:** Passwords in database connection strings and assignment literals replaced with `[REDACTED_SECRET]`.
3. **Private Key Obliteration:** Complete multi-line RSA/EC/OPENSSH private key blocks replaced with `[REDACTED_PRIVATE_KEY]`.
4. **Log Sanitization:** Application log formatter sanitizes log messages before output.
5. **Evidence Length Bounding:** Raw finding code snippets bounded to a maximum of 1,000 characters with ellipsis.
6. **Finding Location Preservation:** Rule ID, filename, and line numbers remain fully preserved for triage.
