# Web Application Security Custom Rules Specification

**File:** `specs/WEB_SECURITY_RULE_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Target:** `backend/app/scanners/custom_rules/web/`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 3, Task 3.4)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

This specification defines custom static detection rules for the **Web Application Security** domain (`canonical_domain: "injection"`, `"input_validation"`, `"other"`).

These rules target prevalent application-level injection and input handling vulnerabilities in web services (FastAPI, Flask, Django, Express), specifically focusing on patterns where user-controlled input flows directly into interpreters or system sinks without sanitization.

### 1.1 Scope of Detections
1. **SQL Injection (SQLi):** Direct string formatting (f-strings, `.format()`, `%` formatting, or concatenation) inside database query execution sinks (`cursor.execute()`, `db.session.execute()`).
2. **Command Injection:** Unsanitized variables passed to system shell execution sinks (`os.system()`, `subprocess.Popen(..., shell=True)`).
3. **Path Traversal:** File system access sinks (`open()`, `fs.readFile()`) receiving dynamic path concatenations without directory confinement or basename sanitization.
4. **Insecure Deserialization:** Arbitrary object deserialization sinks (`pickle.loads()`, `yaml.load(..., Loader=yaml.Loader)`).
5. **Dynamic Code Execution:** Runtime evaluation of dynamic code strings via `eval()` or `exec()`.

---

## 2. Rule Specifications

### Rule 1: `custom.web.sql-injection-fstring`
- **Canonical Domain:** `injection` (CWE-89)
- **Severity:** `high` | **Confidence:** `high`
- **Target Extensions:** `.py`
- **Detection Logic:** Database `.execute()` methods invoked with formatted strings (e.g., `execute(f"SELECT ... {var}")` or `execute("SELECT ... %s" % (var,))`) instead of parameterized queries with separate tuple parameters.

### Rule 2: `custom.web.command-injection-shell`
- **Canonical Domain:** `injection` (CWE-78)
- **Severity:** `high` | **Confidence:** `high`
- **Target Extensions:** `.py`
- **Detection Logic:** Calls to `subprocess` with `shell=True` and formatted command strings, or `os.system()` with formatted f-strings or variable arguments.

### Rule 3: `custom.web.path-traversal-open`
- **Canonical Domain:** `input_validation` (CWE-22)
- **Severity:** `high` | **Confidence:** `medium`
- **Target Extensions:** `.py`, `.js`, `.ts`
- **Detection Logic:** Dynamic variable concatenation inside `open()` or file read calls without path sanitization (e.g. `open(f"{DIR}/{filename}")` or `open(BASE_PATH + req_file)`).

### Rule 4: `custom.web.insecure-pickle-load`
- **Canonical Domain:** `input_validation` (CWE-502)
- **Severity:** `critical` | **Confidence:** `high`
- **Target Extensions:** `.py`
- **Detection Logic:** Use of `pickle.loads()`, `pickle.load()`, or unanchored `yaml.load()` on variable payloads.

### Rule 5: `custom.web.unsafe-eval-exec`
- **Canonical Domain:** `injection` (CWE-95)
- **Severity:** `critical` | **Confidence:** `high`
- **Target Extensions:** `.py`, `.js`, `.ts`
- **Detection Logic:** Invocations of `eval()` or `exec()` with variable expressions.
