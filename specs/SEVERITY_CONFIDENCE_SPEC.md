# Severity and Confidence Specification

- **Document:** `specs/SEVERITY_CONFIDENCE_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Status:** Approved Specification (Phase 1)
- **Version:** 1.0.0

---

## 1. Executive Summary & Core Principle

In vulnerability management and static code analysis, **Severity** and **Confidence** represent orthogonal dimensions of risk:

```
                      SEVERITY vs CONFIDENCE MATRIX

                      [ High Impact / Critical ]
                                 ^
           Needs Triage          |          URGENT ACTION
      (e.g., Heuristic RCE)      |     (e.g., Tainted RCE Sink)
                                 |
   LOW --------------------------+-------------------------> HIGH
 CONFIDENCE                      |                       CONFIDENCE
   (Uncertain / Heuristic)       |                    (Deterministic AST)
                                 |
            Ignore / Deprioritize|          Routine Fix
      (e.g., Test Variable Mock) |    (e.g., Insecure Cookie Flag)
                                 v
                         [ Low Impact ]
```

- **Severity** measures the potential **impact and damage** to confidentiality, integrity, and availability if the vulnerability is successfully exploited by an adversary.
- **Confidence** measures the **certainty of detection**—the likelihood that the identified issue is an authentic, actionable flaw (true positive) rather than an artifact of imprecise static analysis, dead code, or test mocks (false positive).

*Design Mandate:* Scanner adapters and scoring engines in Thread Trace must never conflate severity with confidence. A critical flaw detected with low confidence is not a "medium severity" flaw; it is a **Critical Severity flaw with Low Confidence**, requiring human triage.

---

## 2. Severity Taxonomy & Classification Criteria

Thread Trace normalizes all vulnerability findings into four discrete severity tiers:

### 2.1 Critical (`critical`)
- **Criteria:** Vulnerabilities that permit immediate, severe, and catastrophic compromise of the host system, data store, or cloud environment without requiring special access or complex preconditions.
- **Examples:**
  - Remote Code Execution (RCE) via `eval()`, `exec()`, or unescaped shell commands (`subprocess.Popen(..., shell=True)`).
  - Unauthenticated SQL Injection leading to complete database takeover.
  - Hardcoded production cloud provider credentials (AWS Root/IAM keys, GCP Service Account JSON keys).
  - Private cryptographic signing keys (RSA/Ed25519) checked into repository.
  - Dependencies with published CVSS v3 score >= 9.0 (e.g., Log4Shell-equivalent flaws).
  - Authentication bypass allowing administrative access (e.g., JWT `none` algorithm acceptance).

### 2.2 High (`high`)
- **Criteria:** Severe vulnerabilities that could result in substantial data leakage, system compromise, or unauthorized operations, typically requiring authenticated access, specific user actions, or constrained environments.
- **Examples:**
  - Authenticated SQL Injection or NoSQL Injection.
  - Stored Cross-Site Scripting (XSS) in primary user workflows.
  - Server-Side Request Forgery (SSRF) targeting internal network endpoints or cloud metadata APIs.
  - Disabled TLS/SSL certificate verification (`verify=False`) in HTTP communication.
  - Weak cryptographic password hashing (MD5, SHA1, unsalted hashes) used for user passwords.
  - Dependencies with published CVSS v3 score between 7.0 and 8.9.

### 2.3 Medium (`medium`)
- **Criteria:** Issues that degrade application security, violate defense-in-depth principles, or could be chained with other vulnerabilities to achieve privilege escalation.
- **Examples:**
  - Reflected Cross-Site Scripting (XSS) requiring active social engineering.
  - Insecure Direct Object References (IDOR) with limited data impact.
  - Missing security cookie attributes (`HttpOnly`, `Secure`, `SameSite`).
  - Permissive CORS policies (`Access-Control-Allow-Origin: *`) without sensitive credential allowance.
  - Use of cryptographically insecure pseudo-random number generators (`random`) for security tokens.
  - Dependencies with published CVSS v3 score between 4.0 and 6.9.

### 2.4 Low (`low`)
- **Criteria:** Minor security defects, informational discrepancies, configuration hygiene issues, or deviations from secure coding best practices that carry minimal immediate exploitability.
- **Examples:**
  - Missing non-critical HTTP security headers (e.g., `X-Content-Type-Options`).
  - Verbose error messages exposing internal framework stack traces in non-production files.
  - World-readable permissions on local non-sensitive configuration files.
  - Use of deprecated APIs that do not have active exploits.
  - Dependencies with published CVSS v3 score between 0.1 and 3.9.

---

## 3. Confidence Taxonomy & Classification Criteria

Thread Trace classifies detection confidence into three levels:

### 3.1 High (`high`)
- **Criteria:** Detections backed by deterministic syntactic proofs, validated checksums, or exact version matches.
- **Evidence Characteristics:**
  - AST taint analysis confirming that user input flows directly into an execution sink without sanitization.
  - Secret token matching an explicit provider prefix and passing format/checksum validation (e.g., AWS `AKIA` + 16 alphanumeric characters, GitHub `ghp_` token).
  - Dependency vulnerability identified via exact lockfile hash/version matching a specific CVE (e.g., `package-lock.json` exact resolved version).

### 3.2 Medium (`medium`)
- **Criteria:** Detections where the pattern matches a known security anti-pattern, but full dataflow verification cannot be confirmed statically.
- **Evidence Characteristics:**
  - Syntactic AST match of an unsafe function call without proof that the argument is user-controlled (e.g., Bandit flagging `subprocess.call()` where arguments appear hardcoded).
  - Secret detection matching a generic regex pattern or keyword proximity heuristic (e.g., `password = "xyz123"`).
  - Dependency vulnerability identified in an unpinned manifest (`requirements.txt` with loose version ranges).

### 3.3 Low (`low`)
- **Criteria:** Heuristic detections with high statistical variance, potential test mock context, or ambiguous patterns.
- **Evidence Characteristics:**
  - Pure Shannon-entropy spikes without known token prefixes.
  - Matches occurring inside files located within test directories (`/tests/`, `/spec/`, `/fixtures/`).
  - Generic keyword matching without strong entropy or format structure.

---

## 4. Scanner Severity & Confidence Mapping

### 4.1 Semgrep Mapping Matrix
Semgrep natively provides `severity` (`ERROR`, `WARNING`, `INFO`) and optional `confidence` in rule metadata:

| Semgrep Severity | Rule Category / CWE | Thread Trace Severity | Default Confidence |
|---|---|---|---|
| `ERROR` | Injection (SQLi, Command, SSRF), Auth Bypass, Exposed Secrets | `critical` or `high` | Mapped from `metadata.confidence` (default: `high`) |
| `WARNING` | XSS, CSRF, Insecure Cookies, Insecure Deserialization | `medium` | Mapped from `metadata.confidence` (default: `medium`) |
| `INFO` | Best practices, Deprecated APIs, Code hygiene | `low` | `low` |

### 4.2 Bandit Mapping Matrix
Bandit natively outputs both `issue_severity` and `issue_confidence` (`HIGH`, `MEDIUM`, `LOW`):

| Bandit Severity | Bandit Test ID / Impact | Thread Trace Severity | Bandit Confidence | Thread Trace Confidence |
|---|---|---|---|---|
| `HIGH` | `B602` (Shell=True), `B608` (SQL Format), `B301` (Pickle) | `high` (or `critical` if unescaped shell) | `HIGH` | `high` |
| `MEDIUM` | `B501` (No cert verification), `B303` (MD5/SHA1), `B105` (Hardcoded password) | `medium` | `MEDIUM` | `medium` |
| `LOW` | `B101` (assert_used), `B311` (random), `B404` (import_subprocess) | `low` | `LOW` | `low` |

### 4.3 Gitleaks Mapping Matrix
Gitleaks outputs discrete rules corresponding to secret types:

| Gitleaks Rule Type | Example Rule IDs | Thread Trace Severity | Thread Trace Confidence |
|---|---|---|---|
| Cloud Root / IAM Keys | `aws-access-key-id`, `gcp-service-account`, `azure-client-secret` | `critical` | `high` |
| Private Cryptographic Keys | `private-key`, `pgp-private-key` | `critical` | `high` |
| SaaS / Platform API Keys | `github-pat`, `slack-webhook-url`, `stripe-api-key`, `openai-api-key` | `high` | `high` |
| Generic Password / High Entropy | `generic-api-key`, `generic-password` | `medium` | `medium` (or `low` if short) |

### 4.4 OSV-Scanner (CVE / Advisory) Mapping Matrix
OSV-Scanner results map directly from CVSS v3 base metrics recorded in the advisory:

| CVSS v3 Base Score | Qualitative Rating | Thread Trace Severity | Thread Trace Confidence |
|---|---|---|---|
| 9.0 – 10.0 | Critical | `critical` | `high` (lockfile) / `medium` (manifest) |
| 7.0 – 8.9 | High | `high` | `high` (lockfile) / `medium` (manifest) |
| 4.0 – 6.9 | Medium | `medium` | `high` (lockfile) / `medium` (manifest) |
| 0.1 – 3.9 | Low | `low` | `high` (lockfile) / `medium` (manifest) |
| No CVSS / Unrated | Unspecified | `medium` (Default fallback) | `medium` |

---

## 5. Missing Evidence & Missing Line-Number Handling

### 5.1 Missing Evidence Handling
In certain scenarios, a scanner may report a finding without providing an extractable source code line (e.g., manifest-level package advisories or tool internal errors):
1. **Fallback Evidence Generation:** The scanner adapter must construct a concise, descriptive evidence string rather than leaving `evidence` empty or null:
   - For OSV-Scanner: `"Dependency '<package>' version '<version>' in '<manifest>' matches advisory '<advisory_id>' (<summary>)."`
   - For whole-file configuration checks: `"Configuration file '<file>' lacks mandatory security setting '<setting>'."`
2. **Length Bounding:** Evidence strings must be truncated to a maximum of 1,000 characters to prevent database or API transmission degradation.
3. **Redaction Guarantee:** The fallback or raw evidence string must pass through the redaction filter before assignment to the `evidence` field.

### 5.2 Missing Line-Number Handling
- Line numbers can be legitimately absent (`line: None`) for:
  - Manifest-wide or package-level dependency advisories (`requirements.txt`, `package.json`).
  - Project-level configuration omissions (e.g., missing `.gitignore` rule or missing security policy).
  - Whole-file format issues.
- **Standard Protocol:**
  - `Finding.line` is typed as `int | None = None`.
  - Scanners must pass `None` when a specific source line cannot be determined.
  - Scanners must NEVER invent a dummy line number (e.g., `0` or `-1`).
  - Frontend and reporting modules must render `line: None` gracefully as `"File-level"` or `"Manifest-level"`.

---

## 6. Manual-Review Requirements & Triage Protocol

Automated scanning must flag findings requiring human security verification when:
1. **Disparity Alert:** A finding has `severity: "critical"` or `severity: "high"` with `confidence: "low"` or `confidence: "medium"`.
2. **Test Context:** A finding is located within a recognized test path (`tests/`, `__tests__/`, `mock/`, `fixtures/`). Test files often contain dummy API keys or intentional mock injections that are non-exploitable in production.
3. **Secret Verification:** All secret findings must be manually verified to confirm whether the credential has been revoked or rotated.

---

## 7. False-Positive Considerations & Suppression

To minimize alert fatigue while preventing premature suppression of valid issues:
1. **No Automatic Silencing of High Severity Findings:** High and Critical severity findings are never hidden automatically without documented user or rule suppression.
2. **Standard Inline Suppression Comments:** Scanners must respect established inline code suppression directives:
   - Bandit: `# nosec` or `# nosec: <test_id>`
   - Semgrep: `// nosemgrep: <rule_id>` or `# nosemgrep: <rule_id>`
   - Gitleaks: `.gitleaksignore` file or inline ignore comments
3. **Audit Trail:** Suppressed findings are not deleted; they are marked with an audit flag in scan metadata so security auditors can review suppressed alerts.
