# Configuration and Dependency Custom Rules Specification

**File:** `specs/CONFIG_DEPENDENCY_RULE_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Target:** `backend/app/scanners/custom_rules/config/`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 3, Task 3.6)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

This specification defines custom static detection rules for the **Dependency & Configuration Security** domain (`canonical_domain: "configuration"`, `"dependencies"`).

While OSV-Scanner checks dependency versions against published CVE/GHSA databases, these custom rules evaluate:
1. **Application Configuration Flaws:** Risky configuration defaults, such as debug mode left enabled.
2. **CORS Misconfigurations:** Overly permissive cross-origin resource sharing combining wildcard origins with credential forwarding.
3. **Unpinned Dependency Declarations:** Production dependency specifications lacking deterministic pinning (e.g. `*` wildcards).

---

## 2. Rule Specifications

### Rule 1: `custom.config.debug-mode-enabled`
- **Domain:** `Dependency & Configuration Security` | **Canonical:** `configuration` (CWE-489)
- **Severity:** `high` | **Confidence:** `high`
- **Target Extensions:** `.py`, `.env`, `.json`, `.yaml`, `.yml`
- **Detection Logic:** Static flag assignments setting `DEBUG = True`, `app.run(debug=True)`, or `DEBUG=true`.
- **Exclusions:** Explicit development files (e.g., `test_*.py`, `conftest.py`, `dev.py`).

### Rule 2: `custom.config.wildcard-cors-allow-credentials`
- **Domain:** `Dependency & Configuration Security` | **Canonical:** `configuration` (CWE-942)
- **Severity:** `high` | **Confidence:** `high`
- **Target Extensions:** `.py`, `.js`, `.ts`
- **Detection Logic:** CORS middleware configuration pairing wildcard origins (`allow_origins=["*"]`) with `allow_credentials=True`, which exposes authenticated user sessions to cross-site data exfiltration.

### Rule 3: `custom.config.unpinned-dependency`
- **Domain:** `Dependency & Configuration Security` | **Canonical:** `dependencies` (CWE-1104)
- **Severity:** `medium` | **Confidence:** `high`
- **Target Extensions:** `.txt`, `.json`
- **Detection Logic:** Manifest lines declaring wildcards (e.g. `requests==*` or `"package": "*"`) or unpinned bare names in production `requirements*.txt`.
