# Clean Fixture Specification

- **Document:** `specs/CLEAN_FIXTURE_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Status:** Approved Specification (Phase 5, Task 5.2)
- **Version:** 1.0.0

---

## 1. Objectives & False-Positive Guardrails

Clean test fixtures model industry best-practice software patterns. They ensure that static analysis tools and custom rule packs do not trigger false-positive alerts on standard, secure programming constructs.

### Required Clean Patterns:
1. **Secrets:** Retrieving credentials exclusively through environment variables (`os.environ.get("API_KEY")`) or secure secret vaults.
2. **Web Security:** Parameterized SQL queries using DB-API tuples (`cursor.execute("SELECT * FROM u WHERE id = %s", (uid,))`), safe subprocess execution with token arrays (`subprocess.run(["ls", "-l"], shell=False)`), strict path resolution (`Path(p).resolve().is_relative_to(base)`), safe JSON parsing (`json.loads()`).
3. **Network Security:** TLS verification explicitly enabled (`requests.get(..., verify=True)`), HTTPS transport for all remote endpoints (`https://api.example.com`).
4. **Authentication & Access:** Secure cryptographic password hashing (`argon2`, `bcrypt`, or `hashlib.sha256` with salt), JWT signing keys loaded from secure environment.
5. **Configuration & Dependencies:** Production debug flag disabled (`DEBUG = False`), strict CORS allowlists (`allow_origins=["https://threadtrace.internal"]`), fully pinned dependency specifications (`requests==2.32.3`).

---

## 2. Clean Fixture Directory Structure

```
tests/fixtures/clean/ (and backend/tests/fixtures/clean/)
├── secrets/
│   └── clean_secrets.py
├── web/
│   └── secure_app.py
├── network/
│   └── secure_network.py
├── auth/
│   └── secure_auth.py
└── config/
    ├── clean_settings.py
    └── requirements.txt
```
