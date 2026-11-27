# Repository Execution Test Specification

- **Document:** `specs/REPOSITORY_EXECUTION_TEST_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target File:** `backend/tests/test_repository_execution.py`
- **Status:** Approved Specification (Phase 5, Task 5.9)
- **Version:** 1.0.0

---

## 1. Objectives & Zero-Execution Invariant

Validates that uploaded repositories, build scripts, package installation hooks, and test files are treated strictly as inert text data and are NEVER executed during analysis.

### Prohibitions Tested:
1. **Build Scripts:** `setup.py`, `Makefile`, `build.sh`, `package.json` lifecycle scripts (`preinstall`, `postinstall`) are never executed.
2. **No Dynamic Imports:** Scanners and custom rules parse source using Python's `ast.parse()` or regular expressions; target files are never dynamically imported via `importlib` or `__import__`.
3. **No Pip/Npm Installation:** The scanner environment does not invoke package managers on target manifests.
4. **Tripwire Validation:** Weaponized fixture files containing execution tripwires (e.g., creating a sentinel file on disk if executed) confirm zero execution occurs throughout the entire scan lifecycle.
