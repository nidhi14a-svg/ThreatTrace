# Network and Authentication Custom Rules Specification

**File:** `specs/NETWORK_AUTH_RULE_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Targets:** `backend/app/scanners/custom_rules/auth/`, `backend/app/scanners/custom_rules/network/`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 3, Task 3.5)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

This specification defines custom static detection rules for the **Network & Communication Security** and **Authentication & Access Control** domains.

These rules target network transport insecurities and broken authentication primitives that can lead to credential theft, man-in-the-middle (MITM) tampering, and session compromise.

### 1.1 Core Boundaries
1. **Network vs. Auth Separation:** Transport-layer issues (TLS disabled, cleartext HTTP) belong to `Network & Communication Security` (`cryptography`). Authentication token and credential algorithm issues belong to `Authentication & Access Control` (`authentication` or `authorization`).
2. **Context-Aware Heuristics:** Exclude local loopback addresses (`localhost`, `127.0.0.1`) from cleartext HTTP alerts to prevent false positives during local testing.

---

## 2. Rule Specifications

### Network Rules (`backend/app/scanners/custom_rules/network/`)

#### Rule 1: `custom.network.disabled-tls-verify`
- **Domain:** `Network & Communication Security` | **Canonical:** `cryptography` (CWE-295)
- **Severity:** `high` | **Confidence:** `high`
- **Target Extensions:** `.py`, `.js`, `.ts`
- **Detection Logic:** Explicitly disabling certificate verification (e.g. `requests.get(..., verify=False)`, `httpx.get(..., verify=False)`, or setting `NODE_TLS_REJECT_UNAUTHORIZED = '0'`).

#### Rule 2: `custom.network.cleartext-http-endpoint`
- **Domain:** `Network & Communication Security` | **Canonical:** `cryptography` (CWE-319)
- **Severity:** `medium` | **Confidence:** `medium`
- **Target Extensions:** `.py`, `.js`, `.ts`, `.env`, `.json`
- **Detection Logic:** Hardcoded `http://` URLs for remote external API services (ignoring `http://localhost`, `http://127.0.0.1`, `http://0.0.0.0`, schema URLs like `http://www.w3.org`).

---

### Authentication Rules (`backend/app/scanners/custom_rules/auth/`)

#### Rule 3: `custom.auth.weak-md5-sha1-hashing`
- **Domain:** `Authentication & Access Control` | **Canonical:** `cryptography` (CWE-327)
- **Severity:** `high` | **Confidence:** `high`
- **Target Extensions:** `.py`, `.js`, `.ts`
- **Detection Logic:** Use of deprecated MD5 (`hashlib.md5`) or SHA-1 (`hashlib.sha1`) algorithms, particularly in contexts where passwords, tokens, or digital signatures are computed.

#### Rule 4: `custom.auth.hardcoded-jwt-secret`
- **Domain:** `Authentication & Access Control` | **Canonical:** `authentication` (CWE-798)
- **Severity:** `critical` | **Confidence:** `high`
- **Target Extensions:** `.py`, `.js`, `.ts`
- **Detection Logic:** Cleartext string literals passed as the signing or verification secret in `jwt.encode()` or `jwt.decode()` calls.
