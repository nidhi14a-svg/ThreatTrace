# Five-Domain Security Coverage Specification

**File:** `specs/FIVE_DOMAIN_COVERAGE_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Targets:** `backend/app/scanners/custom_rules/`, `backend/app/scanners/`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 3, Task 3.2)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

Thread Trace employs a two-tier domain taxonomy:
1. **User-Facing Display Taxonomy (5 Domains):** Designed for high-level security reporting, executive dashboards, and intuitive developer filtering.
2. **Canonical Backend Domain Taxonomy (10 Identifiers):** Approved by Dev B in `backend/app/schemas/finding.py` for granular database indexing, search queries, and AI enrichment.

This specification maps the five project-level security domains to the ten canonical backend identifiers, delineates the exact detection capabilities of each scanner engine and custom rule set, and explicitly records known coverage limitations and overlap resolution rules.

---

## 2. Domain Taxonomy Mapping Matrix

| Display Domain (5 Project-Level) | Canonical Backend Domains (10 Identifiers) | Scope & Focus |
|---|---|---|
| **1. Secrets & Sensitive Information Management** | `secrets` | Hardcoded API keys, tokens, private keys, database credentials, exposed environment variables. |
| **2. Web Application Security** | `injection`<br>`input_validation`<br>`other` | SQLi, Command Injection, XSS, Path Traversal, Insecure Deserialization, SSRF, unvalidated redirects. |
| **3. Network & Communication Security** | `cryptography`<br>`logging` | Cleartext HTTP communication, disabled TLS verification, weak cipher suites, sensitive data in logs. |
| **4. Authentication & Access Control** | `authentication`<br>`authorization` | Weak password hashing, hardcoded JWT secrets, broken session management, missing authorization checks. |
| **5. Dependency & Configuration Security** | `dependencies`<br>`configuration` | Known CVEs/GHSAs in third-party packages, debug mode in production, wildcard CORS, insecure container declarations. |

---

## 3. Comprehensive Tool & Custom Rule Coverage Matrix

| Display Domain | Canonical Backend Domain | Semgrep Coverage | Bandit Coverage | Gitleaks Coverage | OSV-Scanner Coverage | Custom Rules Coverage |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **Secrets Management** | `secrets` | Medium (Config & variable checks) | Low (B105/B106 hardcoded passwords) | **Primary (High)** (160+ token formats) | None | **Targeted (High)** (API keys, connection strings, JWT secrets) |
| **Web Security** | `injection` | **Primary (High)** (SQLi, Commandi) | **High** (Python B602, B608) | None | None | **Targeted (High)** (F-string SQLi, os.system, eval/exec) |
| **Web Security** | `input_validation` | **Primary (High)** (XSS, Path traversal) | Medium (B301 pickle, B506 yaml) | None | None | **Targeted (High)** (Path traversal open, unsafe pickle/yaml) |
| **Network Security** | `cryptography` | Medium (Weak hash algorithms) | **High** (B303 MD5, B324 SHA1, B501 TLS) | None | None | **Targeted (High)** (Disabled verify=False, weak MD5/SHA1 hashing) |
| **Network Security** | `logging` | Low (Log injection patterns) | None | None | None | **Targeted (Medium)** (Logging sensitive credentials/tokens) |
| **Auth & Access Control**| `authentication` | **High** (Hardcoded credentials/tokens) | Medium (B105 hardcoded passwords) | Low | None | **Targeted (High)** (Hardcoded JWT secret, weak password algorithms) |
| **Auth & Access Control**| `authorization` | Medium (Missing auth decorators) | Low | None | None | **Targeted (Medium)** (Missing role checks, route bypasses) |
| **Dependency & Config** | `dependencies` | None | None | None | **Primary (High)** (Python, Node, Go, Rust CVEs/GHSAs) | **Targeted (Medium)** (Unpinned wildcard dependencies) |
| **Dependency & Config** | `configuration` | **High** (Framework configs, Docker) | Low (B104 binding all interfaces) | None | None | **Targeted (High)** (Debug mode True, wildcard CORS + credentials) |

---

## 4. Deep-Dive Domain Breakdown

### Domain 1: Secrets & Sensitive Information Management (`secrets`)
- **Primary Scanners:** Gitleaks (raw entropy & regex), Custom Rules (`custom.secrets.*`).
- **Supported Targets:** All text files, source files (`.py`, `.js`, `.ts`, `.env`, `.json`, `.yml`).
- **Security Checks:**
  - Hardcoded cloud provider keys (AWS, GCP, Azure).
  - SaaS platform tokens (GitHub, Slack, Stripe).
  - Database connection strings (`postgresql://`, `mongodb://`, `mysql://`).
  - Private key blocks (RSA, EC, PGP).
- **Known Limitations:** Cannot verify whether a credential is live, revoked, or scoped without external network probes (which are prohibited).

### Domain 2: Web Application Security (`injection`, `input_validation`, `other`)
- **Primary Scanners:** Semgrep (polyglot AST taint), Bandit (Python), Custom Rules (`custom.web.*`).
- **Supported Targets:** Python (`.py`), JavaScript/TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`).
- **Security Checks:**
  - SQL injection via dynamic string formatting / string concatenation into execution sinks.
  - OS command injection via unescaped arguments in `subprocess.Popen`, `os.system`.
  - Path traversal via unsanitized file path concatenation in `open()`.
  - Insecure object deserialization via `pickle.loads()`, `yaml.load(..., Loader=yaml.Loader)`.
- **Known Limitations:** Static analysis cannot guarantee runtime reachability without active DAST/taint execution.

### Domain 3: Network & Communication Security (`cryptography`, `logging`)
- **Primary Scanners:** Bandit, Semgrep, Custom Rules (`custom.network.*`).
- **Supported Targets:** Python source code, API configuration files.
- **Security Checks:**
  - Disabled TLS certificate verification (`verify=False` in requests/httpx/urllib3).
  - Hardcoded cleartext HTTP endpoints for sensitive authentication/payment destinations.
  - Deprecated cryptographic hash algorithms (MD5, SHA1) used in security contexts.
- **Known Limitations:** Custom rules cannot evaluate encrypted network traffic at runtime or inspect middlebox/TLS termination proxies.

### Domain 4: Authentication & Access Control (`authentication`, `authorization`)
- **Primary Scanners:** Semgrep, Custom Rules (`custom.auth.*`).
- **Supported Targets:** Python, JavaScript/TypeScript source code.
- **Security Checks:**
  - Hardcoded JWT signing secrets in code or configuration.
  - Weak password storage algorithms without salting.
  - Insecure default credentials in authentication handlers.
  - Missing authorization checks on sensitive administrative routes.
- **Known Limitations:** Complex role-based access control (RBAC) business logic spanning multiple microservices cannot be completely verified through static AST analysis alone.

### Domain 5: Dependency & Configuration Security (`dependencies`, `configuration`)
- **Primary Scanners:** OSV-Scanner, Custom Rules (`custom.config.*`).
- **Supported Targets:** Manifests (`requirements.txt`, `package.json`, lockfiles), Dockerfiles, `.env`, settings.
- **Security Checks:**
  - Known CVEs and GHSAs in direct and transitive open-source dependencies.
  - Dangerous configuration settings: `DEBUG = True` in production configurations.
  - Permissive CORS settings (`allow_origins=["*"]` combined with `allow_credentials=True`).
  - Container security misconfigurations (running as root user).
- **Known Limitations:** Manifest scanning without lockfiles may produce ambiguous advisory matches when unpinned version ranges (`>=`) are specified.

---

## 5. Overlap & Deduplication Strategy

When both an off-the-shelf scanner (e.g. Bandit) and a custom rule detect the same vulnerability on the same file and line:
1. **Precedence:** Off-the-shelf scanner findings take precedence as the authoritative detection.
2. **Deduplication Key:** Findings sharing `(file, line, canonical_domain)` are deduplicated in Phase 3 Task 3.8.
3. **Complementary Coverage:** Custom rules are designed specifically to target gaps not covered by standard scanner rulepacks (such as project-specific configuration patterns).
