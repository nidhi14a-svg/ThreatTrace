# Temporary Workspace Specification

- **Document:** `specs/TEMP_WORKSPACE_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator / Implementation Owner:** Dev B (Backend Developer)
- **Status:** Approved Specification (Phase 4, Task 4.6)
- **Version:** 1.0.0

---

## 1. Directory Structure & Layout

Ephemeral workspaces isolate each uploaded source code archive during analysis. Workspaces are allocated under a dedicated volume:

`/tmp/thread-trace/workspaces/<workspace_id>/`

Where `<workspace_id>` is a cryptographically secure UUIDv4 generated during upload handling.

### Internal Workspace Layout:
```
/tmp/thread-trace/workspaces/<workspace_id>/
├── source/                 <-- Extracted target repository files (READ-ONLY to scanner)
│   ├── app/
│   ├── package.json
│   └── ...
└── output/                 <-- Scanner raw execution results (WRITEABLE by scanner)
    └── raw_results.json
```

---

## 2. Mount Boundaries & Permission Constraints

1. **Read-Only Source Mount (`:ro`):**
   - The `source/` subdirectory is mounted into the scanner container with read-only permissions (`:ro`).
   - The scanner container cannot modify, corrupt, or drop files in `source/`.
2. **Isolated Output Directory:**
   - The `output/` directory is created with write permissions for `UID 10001` (`chmod 0770`), allowing the unprivileged scanner worker to serialize JSON outputs.
3. **Filesystem Traversal Defenses:**
   - Any path resolution must be validated to ensure it resides strictly within `/tmp/thread-trace/workspaces/`.
   - Paths containing `..`, absolute paths outside the base, or symlink targets outside the workspace must be rejected immediately.

---

## 3. Ownership & Dev B Coordination

- **Dev B Responsibility:**
  - Manages upload staging in `/tmp/thread-trace/uploads/`.
  - Executes safe ZIP extraction into `<workspace_id>/source` using `extraction_service.py` adhering to `ZIP_ARCHIVE_SECURITY_SPEC.md`.
  - Invokes scan orchestration.
- **Dev C Responsibility:**
  - Defines volume mounting flags in `docker-compose.yml`.
  - Enforces `:ro` mounting boundaries on scanner workers.
  - Implements cleanup script and workspace manager utilities to ensure safe deletion.
