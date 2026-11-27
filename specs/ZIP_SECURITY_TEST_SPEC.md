# ZIP Security Test Specification

- **Document:** `specs/ZIP_SECURITY_TEST_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target Files:** `backend/tests/test_zip_security.py`, `backend/tests/test_upload.py`
- **Collaborator / Implementation Owner:** Dev B (Backend Developer)
- **Status:** Approved Specification (Phase 5, Task 5.4)
- **Version:** 1.0.0

---

## 1. Objectives & Threat Coverage

Verifies archive parsing defense requirements documented in `ZIP_ARCHIVE_SECURITY_SPEC.md` to prevent host exploitation, denial-of-service, and filesystem compromise.

### Threat Vectors Tested:
1. **Zip Slip (Directory Traversal):** Archive members containing relative paths (`../../evil.sh`) designed to escape target destination directory.
2. **Absolute Path Traversal:** Archive members specifying root paths (`/etc/passwd` or `C:\Windows\System32`).
3. **Oversized Archives:** Archives exceeding the 100 MB upload threshold.
4. **Excessive Entry Count:** Archives with > 5,000 files designed to exhaust inode tables.
5. **Compression Ratio Bomb:** Small archives uncompressing to > 250 MB (exceeding 100:1 ratio).
6. **Symlink Attacks:** Archives containing symlink entries pointing to external files (`/etc/passwd`).
7. **Duplicate Member Names:** Multiple archive entries with identical target paths to cause race conditions.
8. **Corrupt / Malformed ZIP:** Non-ZIP or truncated byte streams.

---

## 2. Test Coordination Invariants

Dev C provides the security test cases and validation helpers. Tests verify that the extraction boundary rejects malicious archives with clean validation errors without executing extracted files or crashing the backend process.
