# Secrets Management Custom Rules Specification

**File:** `specs/SECRETS_MANAGEMENT_RULE_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Target:** `backend/app/scanners/custom_rules/secrets/`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 3, Task 3.3)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

This specification defines custom static detection rules for the **Secrets & Sensitive Information Management** domain (`canonical_domain: "secrets"`).

While Gitleaks provides general token scanning, these custom rules provide context-aware detection within code syntax and configuration files, targeting:
1. **Hardcoded API Keys & Tokens:** Quoted assignment of sensitive keys to credential variables.
2. **Database Connection Strings:** URIs containing cleartext credentials (`postgresql://`, `mongodb://`, `mysql://`).
3. **Hardcoded Passwords:** Hardcoded authentication passwords in code, avoiding naive keyword matching.
4. **Private Cryptographic Keys:** Unencrypted PEM/DER private keys embedded directly into source files.

### 1.1 False-Positive Minimization Guidelines
A naive regex flagging every instance of the word `password` or `key` produces unacceptable noise. Custom rules must enforce:
- Variable assignment context (`password = "..."` or `"password": "..."`).
- Value inspection: Exclude empty strings, environment lookups (`os.getenv`), and common dummy/template placeholders (`"changeme"`, `"your_key_here"`, `"example"`, `"placeholder"`, `"test"`).
- Minimum length and character diversity heuristics.

### 1.2 Mandatory In-Memory Redaction
No raw credential string may ever appear in finding evidence. All detected secret matches are masked (e.g. `AKIA****************` or `[REDACTED]`) before the finding leaves the rule.

---

## 2. Rule Specifications

### Rule 1: `custom.secrets.hardcoded-api-key`
- **Domain:** `Secrets & Sensitive Information Management` (`secrets`)
- **Severity:** `high` | **Confidence:** `high`
- **Target Extensions:** `.py`, `.js`, `.ts`, `.env`, `.json`, `.yaml`, `.yml`
- **Detection Logic:** Variable assignments where the identifier names an API or access token (`api_key`, `secret_key`, `access_token`, `client_secret`, `auth_token`), assigned a string literal of length >= 16 with mixed alphanumeric characters, excluding common placeholder values.

### Rule 2: `custom.secrets.database-connection-string`
- **Domain:** `Secrets & Sensitive Information Management` (`secrets`)
- **Severity:** `critical` | **Confidence:** `high`
- **Target Extensions:** `.py`, `.js`, `.ts`, `.env`, `.json`, `.yaml`, `.yml`
- **Detection Logic:** Connection URIs matching standard database schemes (`postgresql://`, `mysql://`, `mongodb://`, `redis://`, `amqp://`) with explicit embedded credentials (`<scheme>://<user>:<password>@<host>`).

### Rule 3: `custom.secrets.hardcoded-password`
- **Domain:** `Secrets & Sensitive Information Management` (`secrets`)
- **Severity:** `high` | **Confidence:** `medium`
- **Target Extensions:** `.py`, `.js`, `.ts`, `.env`
- **Detection Logic:** Explicit assignment to password variables (`password = "..."`, `db_password = "..."`, `admin_password = "..."`) containing non-trivial string literals, ignoring placeholders.

### Rule 4: `custom.secrets.private-key-material`
- **Domain:** `Secrets & Sensitive Information Management` (`secrets`)
- **Severity:** `critical` | **Confidence:** `high`
- **Target Extensions:** `.py`, `.js`, `.ts`, `.env`, `.json`, `.pem`, `.key`
- **Detection Logic:** Cleartext private key header patterns (`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`).
