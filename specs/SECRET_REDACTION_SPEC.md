# Comprehensive Secret Redaction Specification

**File:** `specs/SECRET_REDACTION_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Targets:** `backend/app/core/security.py`, `backend/app/scanners/`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 3, Task 3.9)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

In automated security scanning, raw credentials discovered in source code must be cataloged without becoming a new vulnerability. Storing, logging, or transmitting cleartext secrets creates unacceptable secondary attack vectors.

This specification establishes the centralized **Secret Redaction Engine** across the Thread Trace platform:
1. **Zero Secret Leakage Invariant:** Cleartext API keys, passwords, database URIs, tokens, and private keys must **never** appear in logs, raw scanner evidence, normalized finding models, error messages, reports, or AI prompts.
2. **In-Memory Sanitization:** Redaction must be executed in memory at the source before any finding dictionary is returned or logged.
3. **Context Preservation:** Redaction replaces sensitive token substrings with format-preserving masks (e.g. `AKIA****************` or `[REDACTED_PRIVATE_KEY]`), retaining variable names, syntax structure, and line numbers necessary for developers to remediate the issue.
4. **Length Bounding:** Evidence text is bounded to a maximum of 1,000 characters to prevent database or transmission degradation.

---

## 2. Redaction Coverage by Token Class

| Token Class | Raw Token Example Pattern | Redacted Output Format | Replacement Rule |
|---|---|---|---|
| **AWS Access Key ID** | `AKIAIOSFODNN7EXAMPLE` | `AKIA****************` | Preserves prefix `AKIA`, masks remaining 16 chars with `*`. |
| **AWS Secret Key** | 40-character base64 assignment | `aws_secret = [REDACTED_AWS_SECRET]` | Replaces secret value with mask. |
| **GitHub Tokens** | `ghp_abcdefghijklmnopqrstuvwxyz012345` | `[REDACTED_GITHUB_TOKEN]` | Complete token replacement. |
| **Slack Webhook URL** | `https://hooks.slack.com/services/T/B/X` | `https://hooks.slack.com/services/[REDACTED]` | Preserves service path, redacts destination token. |
| **Slack API Token** | `xoxb-1234567890-abcdef` | `[REDACTED_SLACK_TOKEN]` | Complete token replacement. |
| **Private Keys** | `-----BEGIN RSA PRIVATE KEY-----...` | `[REDACTED_PRIVATE_KEY]` | Replaces entire private key block. |
| **Stripe Live Key** | `sk_live_51Abcdef...` | `[REDACTED_STRIPE_KEY]` | Complete token replacement. |
| **Bearer Tokens** | `Authorization: Bearer eyJhbGci...` | `Authorization: Bearer [REDACTED_BEARER_TOKEN]` | Preserves header format, masks token. |
| **Database URIs** | `postgresql://admin:Pass123@host:5432/db` | `postgresql://admin:********@host:5432/db` | Masks password field, preserves user and host. |
| **Password Assigns** | `password = "MySuperSecret123!"` | `password = "********"` | Masks assigned string literal. |

---

## 3. Platform Touchpoints & Defense-in-Depth

```
+---------------------------------------------------------------------------------+
|                       Vulnerability Scanning Pipeline                           |
+---------------------------------------------------------------------------------+
                                       |
    [ Raw Scanner Output ] ---------> In-Memory Redaction (Gitleaks, Semgrep, Custom)
                                       |
    [ Scanner Error / Traceback ] --> Diagnostic Bounding & Path Masking (1,000 chars)
                                       |
    [ Finding Normalization ] ------> Normalizer Redaction Filter (Finding.evidence)
                                       |
    [ Downstream Logging ] ---------> Centralized sanitize_log() filter
                                       |
    [ AI Prompt Enrichment ] -------> AIFindingContext Pre-Dispatch Redaction Gate
                                       |
    [ Report Generation ] ----------> Redacted Evidence Export
```

### 3.1 Defense-in-Depth Invariants
1. **Scanner Layer:** `BaseScanner.redact_evidence()` and `BaseScanner.bound_evidence()` run immediately on raw CLI findings.
2. **Normalizer Layer:** `normalize_raw_finding()` reapplies redaction and bounds evidence to <= 1,000 chars.
3. **Core Security Utility:** `backend/app/core/security.py` provides `redact_secrets()`, `contains_unmasked_secret()`, and `sanitize_log()`.
4. **AI Context Layer:** `AIFindingContext.validate_evidence_safety()` rejects any context containing unmasked tokens.
