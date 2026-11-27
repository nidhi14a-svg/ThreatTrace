# Scanner Limitations Specification

**File:** `specs/SCANNER_LIMITATIONS_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Targets:** `docs/SERVICE_INTERFACES_DEV_C.md`, `README.md`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 6, Task 6.7)  
**Status:** APPROVED & DOCUMENTED  

---

## 1. Overview & Disclaimer

Thread Trace is a static application security testing (SAST) and software composition analysis (SCA) platform.

> [!WARNING]
> **Static Analysis Disclaimer:**  
> Static code analysis tools cannot guarantee the absence of vulnerabilities, prove runtime exploitability, or replace professional human penetration testing. Thread Trace identifies pattern-based security flaws, syntactic weaknesses, known dependency CVEs, and embedded secrets within uploaded text artifacts. Code not evaluated or runtime execution environments fall outside the static scanner boundary.

---

## 2. Supported Languages & Tool Coverage

| Scanner Engine | Primary Supported Languages / Targets | Detection Scope & Specialization |
|---|---|---|
| **Semgrep** | Python, JavaScript, TypeScript, Go, Java, Ruby, C, C++, Dockerfile, YAML, JSON | Semantic pattern matching, syntactic linting, OWASP Top 10 rules. |
| **Bandit** | Python (`.py`) | AST-level security flaw identification (eval/exec, SQLi, shell=True, weak crypto). |
| **Gitleaks** | All text files, source files, configuration files, `.env` | High-entropy string analysis and regex matching for 160+ credential types. |
| **OSV-Scanner** | `requirements.txt`, `package.json`, `package-lock.json`, `go.mod`, `Cargo.lock` | Open Source Vulnerability (OSV) database advisory matching (CVEs/GHSAs). |
| **Custom AST Rules** | Python (`.py`), requirements manifests, environment files | High-fidelity checks for FastAPI, Flask, Django patterns, unpinned deps, CORS. |

---

## 3. Unsupported Languages & Excluded File Formats

1. **Compiled & Binary Artifacts:**
   - Compiled executable binaries (`.exe`, `.dll`, `.so`, `.dylib`), ELF binaries, object files (`.o`), and Java bytecode (`.class`, `.jar`, `.war`) are **not** decompiled or inspected.
2. **Proprietary & Domain-Specific Languages:**
   - Legacy languages (COBOL, Fortran, RPG, Assembly) and proprietary DSP scripts are unsupported.
3. **Nested & Encrypted Archives:**
   - Archives within archives (`.zip` inside `.zip`, `.tar.gz`, `.rar`, `.7z`) and password-protected/encrypted files are rejected during ingestion or skipped.
4. **Media & Binary Assets:**
   - Image (`.png`, `.jpg`), audio, video, font files, and SQLite database binaries (`.db`, `.sqlite3`) are skipped.

---

## 4. Fundamental Static Analysis Limitations

### 4.1 Cross-File & Interprocedural Taint Limitations
- Thread Trace scanners analyze files independently or within single-file AST boundaries.
- Complex data flows where untrusted user input enters via one microservice/controller, passes through multiple asynchronous message queues or ORM layers, and sinks into an execution primitive in a separate module cannot be verified statically without extensive symbolic execution.

### 4.2 Dynamic & Runtime Vulnerabilities
- Race conditions, Time-of-Check to Time-of-Use (TOCTOU) flaws, and thread-safety bugs are rarely detectable via AST patterns.
- Memory corruption vulnerabilities (use-after-free, double-free, heap overflows in C/C++ extensions) require dynamic instrumentation (ASan, Valgrind, fuzzing).
- Business logic bypasses (e.g. manipulating checkout basket totals, skipping multi-factor authentication steps) cannot be determined without understanding application domain semantics.

### 4.3 Dependency & Manifest Scanning Limitations
- **Manifests Without Lockfiles:** Scanning unpinned requirements (e.g. `requests>=2.0.0`) cannot guarantee which specific minor/patch version will be resolved at build time, leading to potential advisory mismatch.
- **Vendored / Inlined Dependencies:** Third-party libraries copied directly into source trees without manifest declarations are not indexed by SCA engines.
- **Transitive Dependencies in Incomplete Manifests:** Without dependency lockfiles, transitive packages are invisible to static manifest parsers.

### 4.4 False Positives & False Negatives
- **False Positives:** High-entropy strings (e.g. cryptographic hashes, UUIDs, base64 assets, synthetic test vectors) may trigger secret alerts despite safe suppressions.
- **False Negatives:** Dynamic code generation (`eval(base64_decode(...))`), runtime string concatenation (`"se" + "cret"`), or obfuscated payloads bypass regex and AST patterns.

---

## 5. Conditions Requiring Manual Security Assessment

Static scanner reports should be followed by manual code review and penetration testing under the following conditions:
1. **Critical Authentication & Authorization Modules:** Custom cryptographic implementations, bespoke OAuth/OIDC handlers, and complex RBAC authorization decorators.
2. **High-Risk Integrations:** Healthcare data processing (HIPAA), payment processing (PCI-DSS), and export-controlled cryptography.
3. **External System Interfaces:** Unvalidated IPC sockets, microservice RPC definitions, and cloud infrastructure IAM policies.
4. **Findings with Low Confidence:** Any scanner finding marked `confidence: "low"` requires human verification before deploying mitigations.
