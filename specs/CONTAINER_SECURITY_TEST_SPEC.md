# Container Security Test Specification

- **Document:** `specs/CONTAINER_SECURITY_TEST_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Target File:** `backend/tests/test_container_security.py`
- **Status:** Approved Specification (Phase 5, Task 5.8)
- **Version:** 1.0.0

---

## 1. Objectives & Infrastructure Assertions

Verifies container configurations, permission models, isolation policies, and filesystem boundaries.

### Assertions Tested:
1. **Unprivileged Context:** Scanner executes as UID `10001` (user `scanner`).
2. **Root Filesystem Immutability:** `read_only: true` configured on scanner worker.
3. **Capabilities:** `cap_drop: [ALL]` drops all Linux capabilities.
4. **Privilege Boundary:** `security_opt: [no-new-privileges:true]` blocks setuid escalation.
5. **Network Air-Gap:** `scanner-net` has `internal: true`; scanner container cannot route to `mongodb:27017` or external internet.
6. **Resource Limits:** CPU (`2.0`), RAM (`1536M`), disabled swap, and PIDs (`100`) strictly defined.
7. **Workspace Mounting:** Source code mounted `:ro`; write access limited to isolated output directory and tmpfs `/tmp`.
