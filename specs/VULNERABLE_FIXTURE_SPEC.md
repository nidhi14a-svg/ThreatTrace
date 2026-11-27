# Vulnerable Fixture Specification

- **Document:** `specs/VULNERABLE_FIXTURE_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Status:** Approved Specification (Phase 5, Task 5.1)
- **Version:** 1.0.0

---

## 1. Objectives & Safety Invariants

Vulnerable test fixtures provide deterministic, reproducible test vectors to validate the detection accuracy of Semgrep, Bandit, Gitleaks, OSV-Scanner, and the Thread Trace Custom Rule Pack.

### Mandatory Safety Invariants:
1. **Zero Real Credentials:** Under no circumstances may active, real, or production API keys, tokens, passwords, or cryptographic keypairs be used. All secrets must be synthetic RFC-compliant tokens or explicitly invalidated test tokens (e.g. `AKIAIOSFODNN7EXAMPLE`).
2. **Zero Live Exploits:** No active malware, weaponized binary payloads, exploit staging code, or denial-of-service scripts may be embedded in fixtures.
3. **Contained Manifests:** Dependency manifests must reference well-documented synthetic vulnerable packages or known historical CVEs without executing installation hooks during tests.

---

## 2. Five-Domain Vulnerable Fixture Inventory

| Domain | File Path | Injected Vulnerability Pattern | Target Scanner(s) |
|---|---|---|---|
| **Secrets Management** | `secrets/hardcoded_secrets.py` | Fake AWS Access Key (`AKIA...`), GitHub PAT (`ghp_...`), private RSA block, raw database URI with password | Gitleaks, Custom Rules (`custom.secrets.*`) |
| **Web Security** | `web/vulnerable_app.py` | SQL injection in f-string, command injection via `subprocess.Popen(..., shell=True)`, path traversal in `open()`, insecure `pickle.loads()`, `eval()` of user input | Semgrep, Bandit (`B602`, `B301`, `B307`, `B608`), Custom Rules (`custom.web.*`) |
| **Network Security** | `network/insecure_network.py` | `requests.get(..., verify=False)`, cleartext HTTP API endpoint (`http://api.internal.corp`) | Bandit (`B501`), Custom Rules (`custom.network.*`) |
| **Authentication & Access** | `auth/insecure_auth.py` | `hashlib.md5()` password hashing, hardcoded JWT secret in `jwt.encode(..., key="secret")` | Bandit (`B303`), Custom Rules (`custom.auth.*`) |
| **Configuration & Dependencies** | `config/settings.py`, `config/requirements.txt` | `DEBUG = True`, Wildcard CORS with credentials (`allow_origins=["*"], allow_credentials=True`), unpinned dependencies (`flask`, `requests>=2.0`) | Custom Rules (`custom.config.*`), OSV-Scanner |

---

## 3. Fixture Directory Structure

```
tests/fixtures/vulnerable/ (and backend/tests/fixtures/vulnerable/)
├── secrets/
│   └── hardcoded_secrets.py
├── web/
│   └── vulnerable_app.py
├── network/
│   └── insecure_network.py
├── auth/
│   └── insecure_auth.py
└── config/
    ├── settings.py
    └── requirements.txt
```
