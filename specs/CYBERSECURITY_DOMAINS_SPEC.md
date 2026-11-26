# Cybersecurity Domains Specification

- **Document:** `specs/CYBERSECURITY_DOMAINS_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Status:** Approved Specification (Phase 1)
- **Version:** 1.0.0

---

## 1. Executive Summary & Purpose

Thread Trace organizes all static source-code security detections into five canonical cybersecurity domains. This taxonomy ensures consistent classification across disparate security scanners, uniform finding aggregation, and structured reporting for developers and security analysts.

Every detection rule, scanner adapter, and normalized finding in Thread Trace must map to exactly one of the five canonical domains:
1. `Secrets & Sensitive Information Management`
2. `Web Application Security`
3. `Network & Communication Security`
4. `Authentication & Access Control`
5. `Dependency & Configuration Security`

This specification defines the scope, vulnerability classifications, detection strategies, supported scanner tools, technical limitations, and standardized finding examples for each domain.

---

## 2. Canonical Domain Reference Table

| Canonical Domain Key | Display Name | Primary Scanner Engine(s) | Detection Methods |
|---|---|---|---|
| `secrets_management` | Secrets & Sensitive Information Management | Gitleaks / detect-secrets, Semgrep (secrets pack), Custom regex | Regex pattern matching, Shannon entropy, prefix/checksum verification |
| `web_security` | Web Application Security | Semgrep (OWASP / Web packs), Bandit (web rules), Custom AST rules | AST matching, source-to-sink taint analysis, unsafe API linter |
| `network_security` | Network & Communication Security | Bandit (crypto/network), Semgrep, Custom rules | AST client pattern analysis, cleartext protocol heuristics, TLS configuration inspection |
| `auth_access_control` | Authentication & Access Control | Semgrep, Bandit (crypto/auth), Custom rules | Decorator/middleware checking, token validation rules, cryptographic strength analysis |
| `dependency_config` | Dependency & Configuration Security | OSV-Scanner, Semgrep (config/framework), Custom parsers | Manifest dependency graph resolution, OSV/CVE advisory lookup, config linter |

---

## 3. Domain 1: Secrets & Sensitive Information Management

### 3.1 Purpose & Scope
This domain covers the detection, isolation, and remediation of unencrypted credentials, cryptographic keys, authentication tokens, and sensitive system parameters inadvertently embedded into application source code, configuration files, or build artifacts.

### 3.2 Types of Vulnerabilities Covered
- **Cloud Provider Credentials:** AWS Access Keys / Secret Keys, Google Cloud Platform service account JSON keys, Azure Client Secrets.
- **API Keys & Webhook Tokens:** Stripe, OpenAI, Anthropic, GitHub Personal Access Tokens (PATs), Slack webhooks, SendGrid API keys.
- **Database & Service Connection Strings:** Hardcoded URIs containing cleartext credentials (e.g., `postgresql://admin:password@host/db`).
- **Cryptographic Material:** Private keys (RSA, ECDSA, Ed25519) in PEM/DER formats, PKCS#12 bundles, hardcoded encryption salts or initialization vectors (IVs).
- **Authentication Secrets:** Hardcoded JWT signing secrets, HMAC keys, password hashes embedded in code or test fixtures.
- **Personal Data & Sensitive Identifiers:** Embedded personally identifiable information (PII) or unencrypted tokens in test data or code comments.

### 3.3 Potential Detection Approaches
- **High-Entropy Analysis:** Shannon entropy calculation across token-like strings to identify high-randomness cryptographic secrets.
- **Regex Pattern Matching:** Deterministic regular expressions matching well-defined secret structures (e.g., AWS `AKIA[0-9A-Z]{16}`, GitHub `ghp_[0-9a-zA-Z]{36}`).
- **Keyword & Context Proximity Heuristics:** Semantic proximity analysis scanning for variable assignments containing keywords (`api_key`, `secret`, `password`, `token`) paired with string literals.
- **Known-Format Validation:** Checksum and format validation algorithms (e.g., Luhn check for payment card numbers, base64 length checking).

### 3.4 Relevant Scanner Tools
- **Gitleaks:** Dedicated secret scanner utilizing regex and Shannon entropy rules.
- **detect-secrets:** Baseline-driven secret scanner utilizing plugin heuristics.
- **Semgrep:** Pattern matching on language-specific secret assignments and configuration keys.
- **Custom Security Rules:** Tailored regex and AST checks for proprietary internal tokens and connection string structures.

### 3.5 Detection Limitations
- **No Active Live Probing:** Scanners operate strictly static and offline; they cannot and must not make out-of-band network calls to verify if an exposed key is live, revoked, or active.
- **High Entropy False Positives:** Hashes, UUIDs, cryptographic nonces, base64-encoded binary assets, and synthetic test values frequently trigger entropy alerts.
- **Obfuscated / Split Strings:** Strings concatenated dynamically at runtime (e.g., `"sec" + "ret"`) or decoded from external files bypass static regex matching.
- **Compiled / Binary Payloads:** Secret scanning in Thread Trace is constrained to text-based source and configuration files; compiled binaries or archives within archives are excluded.

### 3.6 Example Findings
```json
{
  "domain": "Secrets & Sensitive Information Management",
  "rule_id": "gitleaks.aws-access-key-id",
  "title": "Hardcoded AWS Access Key ID Detected",
  "severity": "critical",
  "confidence": "high",
  "file": "backend/app/core/config.py",
  "line": 14,
  "evidence": "AWS_ACCESS_KEY = \"AKIA****************\"",
  "tool": "gitleaks",
  "recommendation": "Remove hardcoded credentials immediately. Rotate the exposed key in the AWS IAM Console, and load credentials from environment variables or IAM instance roles."
}
```

---

## 4. Domain 2: Web Application Security

### 4.1 Purpose & Scope
This domain focuses on detecting standard web application security flaws outlined in the OWASP Top 10, CWE Top 25, and relevant secure coding standards within application controllers, routes, views, and data access layers.

### 4.2 Types of Vulnerabilities Covered
- **Injection Flaws:** SQL Injection (SQLi), NoSQL Injection, Command Injection (OS command execution), Lightweight Directory Access Protocol (LDAP) injection.
- **Cross-Site Scripting (XSS):** Reflected XSS, Stored XSS, and Client-Side DOM XSS via unescaped template rendering or unsafe DOM sinks (e.g., `dangerouslySetInnerHTML`).
- **Server-Side Request Forgery (SSRF):** Unvalidated URL parameters passed directly to HTTP clients (`requests`, `httpx`, `fetch`, `axios`).
- **Path Traversal / Local File Inclusion (LFI):** User-controlled input supplied to file system APIs (`open`, `readFile`, `os.path.join`) without canonical path boundary enforcement.
- **Insecure Deserialization:** Unsafe parsing of untrusted serialized objects (e.g., Python `pickle.loads()`, `yaml.load()` without SafeLoader).
- **Cross-Origin Resource Sharing (CORS) Misconfigurations:** Permissive CORS wildcards (`Access-Control-Allow-Origin: *`) paired with credentials.
- **Open Redirects:** Unvalidated user redirection inputs passed to HTTP redirect responses.

### 4.3 Potential Detection Approaches
- **Abstract Syntax Tree (AST) Matching:** Identifying invocations of inherently dangerous functions (`eval`, `exec`, `os.system`, `subprocess.Popen(..., shell=True)`).
- **Intra-file Taint Tracking:** Tracking untrusted user input sources (e.g., HTTP request query params, body) to execution sinks (database queries, file operations, command shells) within a single compilation unit.
- **Semantic Code Pattern Search:** Identifying insecure API usage such as raw string interpolation in SQL query construction (`f"SELECT * FROM users WHERE id = '{user_id}'"`).

### 4.4 Relevant Scanner Tools
- **Semgrep:** Primary engine for multi-language AST pattern matching and intra-file taint analysis.
- **Bandit:** Python-specific security linter analyzing AST nodes for dangerous imports and calls (e.g., `B602: subprocess_popen_with_shell_equals_true`, `B608: hardcoded_sql_expressions`).
- **Custom Security Rules:** Project-tailored rules detecting framework-specific unsafe practices (e.g., FastAPI raw SQL queries or React unescaped rendering).

### 4.5 Detection Limitations
- **Inter-file Data Flow Limits:** Standard open-source static analysis cannot reliably track complex taint flows traversing multiple microservices, asynchronous message queues, or deep multi-module class hierarchies without proprietary engines.
- **Dynamic Reflection & Metaprogramming:** Python's `getattr()`, `importlib`, or JavaScript dynamic property access (`obj[var]()`) cannot be fully resolved statically.
- **Business Logic Flaws:** Scanners cannot understand functional business logic (e.g., whether a discount code can be applied twice or if an auction bid price is logically invalid).
- **Client-Side Framework Sanitization:** Modern UI frameworks (React, Next.js) automatically escape dynamic values; regex-based scanners may raise false positives on benign JSX expressions.

### 4.6 Example Findings
```json
{
  "domain": "Web Application Security",
  "rule_id": "semgrep.python.fastapi.security.sql-injection-format-string",
  "title": "SQL Query Formatted with Untrusted Input",
  "severity": "high",
  "confidence": "high",
  "file": "backend/app/api/routes/users.py",
  "line": 42,
  "evidence": "query = f\"SELECT * FROM users WHERE email = '{user_input}'\"",
  "tool": "semgrep",
  "recommendation": "Use parameterized queries or an ORM/query builder to bind user input safely rather than formatting SQL strings directly."
}
```

---

## 5. Domain 3: Network & Communication Security

### 5.1 Purpose & Scope
This domain evaluates how the application establishes network connections, configures cryptographic transport protocols, validates server identities, and communicates across internal and external boundaries.

### 5.2 Types of Vulnerabilities Covered
- **Cleartext Protocol Usage:** Use of unencrypted protocols for sensitive operations (e.g., `http://`, `ftp://`, `telnet://`).
- **Disabled TLS/SSL Verification:** Explicitly bypassing certificate checks (e.g., `requests.get(..., verify=False)`, `RejectUnauthorized: false`, custom non-validating SSL contexts).
- **Insecure TLS Versions & Weak Ciphers:** Hardcoding deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) or insecure cipher suites (RC4, 3DES, MD5).
- **Hardcoded Internal Hostnames & Sensitive IP Addresses:** Hardcoding internal private IPs (e.g., `10.0.0.0/8`, `192.168.0.0/16`) or cloud metadata endpoints (`169.254.169.254`).
- **Insecure WebSocket / Socket Implementations:** Establishing unencrypted WebSocket connections (`ws://` instead of `wss://`) carrying sensitive tokens or user state.

### 5.3 Potential Detection Approaches
- **Client Invocations AST Analysis:** Scanning arguments to network libraries (`requests`, `httpx`, `aiohttp`, `fetch`, `axios`) for disabled security flags.
- **Socket and SSL Context Linting:** Inspecting calls to `ssl.create_default_context()`, `ssl.wrap_socket()`, or custom socket configurations.
- **URL & Address Regex Analysis:** Detecting cleartext URL schemes in string constants and configuration files.

### 5.4 Relevant Scanner Tools
- **Bandit:** Rules covering insecure SSL/TLS configurations (e.g., `B501: request_with_no_cert_validation`, `B502: ssl_with_bad_version`, `B503: ssl_with_bad_defaults`).
- **Semgrep:** Rules scanning for cleartext URLs, unverified certificates in JavaScript and Python, and unsafe network calls.
- **Custom Security Rules:** Policy rules detecting hardcoded cloud metadata endpoints or corporate internal subnet references.

### 5.5 Detection Limitations
- **Infrastructure-as-Code & Dynamic Infrastructure:** Static source scanners cannot verify cloud load balancer TLS termination, reverse proxy (Nginx, Envoy) SSL certificates, or Kubernetes service mesh mTLS configurations.
- **Environment-Driven URLs:** Endpoints constructed via environment variables (e.g., `f"{settings.SERVICE_URL}/endpoint"`) cannot have their protocol scheme validated statically if the variable is populated at runtime.
- **VPN / Overlay Networks:** Internal communication over secure private overlays cannot be distinguished from cleartext exposure on public networks based on code alone.

### 5.6 Example Findings
```json
{
  "domain": "Network & Communication Security",
  "rule_id": "bandit.B501.requests_no_cert_validation",
  "title": "Certificate Verification Disabled in HTTP Request",
  "severity": "high",
  "confidence": "high",
  "file": "backend/app/services/external_client.py",
  "line": 28,
  "evidence": "response = requests.get(api_url, verify=False, timeout=10)",
  "tool": "bandit",
  "recommendation": "Set 'verify=True' or pass the path to a trusted CA bundle to prevent Man-in-the-Middle (MitM) attacks."
}
```

---

## 6. Domain 4: Authentication & Access Control

### 6.1 Purpose & Scope
This domain covers the mechanisms governing identity verification, session preservation, cryptographic token handling, permission enforcement, and access authorization across application endpoints and services.

### 6.2 Types of Vulnerabilities Covered
- **Missing or Broken Authentication:** Publicly exposed administrative or protected routes missing required authentication middleware or decorators (e.g., missing `@requires_auth`).
- **Weak Password Hashing Algorithms:** Use of broken or un-salted hash algorithms (e.g., MD5, SHA-1, plain SHA-256 without key stretching) for credentials instead of bcrypt, Argon2, or PBKDF2.
- **JWT Misconfiguration:** Bypassing JWT signature verification, accepting the `none` algorithm, or using symmetric signing keys with weak entropy.
- **Insecure Session Cookie Flags:** Missing `Secure`, `HttpOnly`, or `SameSite` flags when configuring session cookies in web frameworks.
- **Insecure Direct Object References (IDOR):** Direct lookup of entities by identifier without tenant or ownership verification in controller methods.
- **Default / Hardcoded Credentials:** Use of fallback admin credentials (e.g., `if user == "admin" and password == "admin":`).

### 6.3 Potential Detection Approaches
- **Framework Route Decorator Auditing:** Verifying that route definitions in frameworks (FastAPI, Express, Django) include authorization dependencies or middleware.
- **Cryptographic Library Usage Auditing:** Inspecting imports and function calls to cryptographic primitives (e.g., `hashlib.md5()`, `crypto.createCipher()`).
- **Cookie & Header Configuration Matching:** Verifying response cookie setting calls for security attributes (`httponly=True, secure=True, samesite="Lax"`).
- **JWT Verification Parameter Matching:** Inspecting `jwt.decode()` calls to ensure `algorithms` are restricted and `options={"verify_signature": False}` is absent.

### 6.4 Relevant Scanner Tools
- **Semgrep:** Rich framework rules auditing FastAPI, Express, Next.js, and Flask authentication patterns.
- **Bandit:** Rules flagging weak cryptographic hashing (e.g., `B303: md5`, `B324: hashlib_new_insecure_functions`).
- **Custom Security Rules:** Project-tailored checks verifying that all routes in `/api/v1/admin/` enforce role-based authorization dependencies.

### 6.5 Detection Limitations
- **Complex Authorization Logic:** Static analysis cannot verify whether the fine-grained permissions stored in a database (e.g., tenant roles, ABAC attributes) are correctly evaluated in multi-tenant contexts.
- **Session Store Lifecycle:** Storage and invalidation of server-side sessions (e.g., Redis TTL, token revocation lists) happen at runtime outside static code visibility.
- **Third-Party Identity Providers (IdP):** OpenID Connect (OIDC) or SAML configurations on external providers (Okta, Auth0, Google Identity) cannot be inspected from application code alone.

### 6.6 Example Findings
```json
{
  "domain": "Authentication & Access Control",
  "rule_id": "semgrep.python.jwt.jwt-python-none-algorithm",
  "title": "JWT Signature Verification Configured with 'none' Algorithm",
  "severity": "critical",
  "confidence": "high",
  "file": "backend/app/core/auth.py",
  "line": 35,
  "evidence": "payload = jwt.decode(token, verify=False, algorithms=[\"none\"])",
  "tool": "semgrep",
  "recommendation": "Require cryptographic signature verification with a secure algorithm (e.g., 'HS256' or 'RS256') and supply a strong secret or public key."
}
```

---

## 7. Domain 5: Dependency & Configuration Security

### 7.1 Purpose & Scope
This domain evaluates third-party dependencies, package manifests, lockfiles, and application configuration files for known Common Vulnerabilities and Exposures (CVEs), outdated components, insecure defaults, and operational misconfigurations.

### 7.2 Types of Vulnerabilities Covered
- **Vulnerable Open-Source Dependencies (Software Composition Analysis - SCA):** Components with known CVEs or GitHub Security Advisories (GHSA) listed in `requirements.txt`, `package.json`, `package-lock.json`, etc.
- **Overly Permissive Dependency Pinning:** Using unbound or loose version constraints (e.g., `requests = "*"`) allowing automatic pulls of compromised or broken upstream versions.
- **Insecure Application Configuration Flags:** Enabling debug mode in production (e.g., `DEBUG = True`, `fastapi(debug=True)`), exposing detailed tracebacks and memory contents.
- **Exposed Management & Diagnostic Endpoints:** Enabling unrestricted Swagger/OpenAPI docs or profiling endpoints in non-development deployments.
- **Permissive File Permissions & Dangerous File Operations:** Creating files with world-writable permissions (`chmod 0777`) or insecure temporary file creation (`tempfile.mktemp()`).

### 7.3 Potential Detection Approaches
- **Manifest Graph Resolution & Advisory Querying:** Parsing dependency manifests and lockfiles, extracting package names and version hashes, and querying public vulnerability databases (OSV, NVD, PyPI, npm advisory databases).
- **Configuration File Semantic Linting:** Parsing JSON, YAML, TOML, and INI configuration files to identify insecure key-value pairs (`debug: true`, `bind: "0.0.0.0"`).
- **Framework Initialization AST Auditing:** Inspecting application bootstrap code for insecure settings during app initialization.

### 7.4 Relevant Scanner Tools
- **OSV-Scanner:** Google's open-source dependency vulnerability scanner querying the OSV database for known package advisories.
- **Semgrep:** Configuration and framework security rules analyzing JSON, YAML, and configuration code files.
- **Bandit:** Checks for insecure file permissions and temp file functions (e.g., `B103: set_bad_file_permissions`, `B306: mktemp_q`).
- **Custom Security Rules:** Custom validators for application configuration schemas and environment variable validations.

### 7.5 Detection Limitations
- **No Static Reachability Verification:** OSV-Scanner checks package version numbers against advisory databases. It cannot determine whether the vulnerable function inside the third-party library is actually called (reachable) by the application code.
- **Private & Internal Packages:** Proprietary internal packages not published to public repositories have no public CVE records in OSV/NVD and require internal tracking.
- **Dynamic Dependency Installation:** Dependencies installed dynamically at runtime via setup scripts (`setup.py` custom code) cannot be captured from static lockfiles.
- **Transitive Dependency Drift:** Manifests without lockfiles (`requirements.txt` with loose ranges) cannot be deterministically resolved without a package manager resolution pass.

### 7.6 Example Findings
```json
{
  "domain": "Dependency & Configuration Security",
  "rule_id": "osv.GHSA-xxxx-yyyy-zzzz",
  "title": "Known Critical Vulnerability in Urllib3 (CVE-2023-45803)",
  "severity": "critical",
  "confidence": "high",
  "file": "backend/requirements.txt",
  "line": null,
  "evidence": "urllib3==1.26.17 is vulnerable to request body leak on redirect",
  "tool": "osv-scanner",
  "recommendation": "Upgrade urllib3 to version 1.26.18 or >= 2.0.7 as recommended by GHSA-xxxx-yyyy-zzzz."
}
```

---

## 8. Cross-Domain Mapping and Tool Intersection

Several vulnerabilities can span multiple domains depending on context. To prevent duplicate reporting or inconsistent categorization across scanner modules, Thread Trace establishes the following domain precedence and mapping rules:

| Ambiguous Vulnerability Pattern | Primary Assigned Domain | Rationale |
|---|---|---|
| Hardcoded database password in connection string | `Secrets & Sensitive Information Management` | The root security defect is the exposed credential, regardless of the protocol. |
| Insecure HTTP endpoint in connection string without credentials | `Network & Communication Security` | The defect is cleartext transmission, not secret exposure. |
| Weak password hash algorithm in auth service | `Authentication & Access Control` | The defect directly impacts credential security and identity verification. |
| Known CVE in web framework package (e.g., FastAPI XSS) | `Dependency & Configuration Security` | The defect exists in an external dependency package advisory, not first-party source code. |
| First-party SQL injection in web controller | `Web Application Security` | The defect is introduced in application source code. |
| Enabling `DEBUG=True` in production config | `Dependency & Configuration Security` | Configuration misconfiguration defect. |

---

## 9. Domain Identification & Normalization Standard

To ensure schema compatibility across backend, database, and frontend representations:
1. The **exact domain string** stored in the database and returned in API responses must match the canonical display title:
   - `"Secrets & Sensitive Information Management"`
   - `"Web Application Security"`
   - `"Network & Communication Security"`
   - `"Authentication & Access Control"`
   - `"Dependency & Configuration Security"`
2. For programmatic routing or URL slug generation, the standardized snake_case keys are:
   - `secrets_management`
   - `web_security`
   - `network_security`
   - `auth_access_control`
   - `dependency_config`
3. Every scanner adapter must normalize raw scanner domain outputs into one of these five approved strings. Unknown or unmapped findings must default to the most applicable domain or be flagged during Phase 3 rule normalization.
