# ZIP Archive Security Specification

- **Document:** `specs/ZIP_ARCHIVE_SECURITY_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Collaborator / Implementation Owner:** Dev B (Backend Developer)
- **Implementation References:** `backend/app/services/extraction_service.py`, `backend/app/utils/file_utils.py`
- **Status:** Approved Specification (Phase 1)
- **Version:** 1.0.0

---

## 1. Executive Summary & Purpose

Thread Trace allows users to upload source-code repositories as compressed ZIP archives. Archive processing represents a critical attack surface because malicious archives can induce server-side path traversal (Zip Slip), denial of service via decompression bombs (Zip Bombs), file system exhaustion, or symlink-based arbitrary file reads.

This specification sets forth mandatory security invariants and validation gates for archive ingestion. It explicitly delineates **Dev C's cybersecurity requirements** from **Dev B's backend implementation responsibilities**, ensuring clean ownership without uncoordinated modifications to shared code.

---

## 2. Threat Model for Archive Ingestion

```
+------------------------------------------------------------------------+
|                      INGESTION DEFENSE PIPELINE                        |
|                                                                        |
|  [ Inbound Upload ]                                                    |
|         |                                                              |
|         v                                                              |
|  [ Gate 1: Archive Size & Magic Bytes ]                                |
|         | (Reject if > 100MB, corrupt header, or encrypted)            |
|         v                                                              |
|  [ Gate 2: Table of Contents Inspection (No disk write) ]              |
|         | - Count entries (Reject if > 5,000 files)                    |
|         | - Cumulative uncompressed size (Reject if > 250MB)           |
|         | - Compression ratio check (Reject if ratio > 100:1)          |
|         | - Inspect names for '..' or leading '/' (Zip Slip rejection) |
|         | - Inspect file modes (Reject Symlinks / Special devices)     |
|         v                                                              |
|  [ Gate 3: Safe Extraction to Isolated Workspace ]                     |
|         | - Canonical commonpath boundary verification                 |
|         | - Strict permissions (0700)                                  |
|         v                                                              |
|  [ Scanners Mount Read-Only ] ---> [ Immediate Post-Scan Cleanup ]     |
+------------------------------------------------------------------------+
```

### Primary Attack Vectors Mitigated:
1. **Zip Slip (Arbitrary File Overwrite / Traversal):** Archive members with paths such as `../../etc/cron.d/malicious` or `../../app/main.py` engineered to escape the target extraction directory and overwrite host or application files.
2. **Decompression Bomb (Zip Bomb DoS):** Highly compressed tiny archives (e.g., 42.zip, nested zeros) that expand to hundreds of gigabytes, consuming all host disk space or memory.
3. **Inode Exhaustion:** Archives containing tens of thousands of tiny or empty files designed to exhaust filesystem inodes.
4. **Symlink / Hardlink Exploitation:** Archives containing symbolic links pointing to sensitive system files (e.g., `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`) which, when read by scanners, leak host secrets.
5. **Duplicate Entry Shadowing:** Archives containing multiple entries with identical relative paths to subvert signature verification or scanners.
6. **Encrypted / Password-Protected Archives:** Archives requiring passwords which cannot be statically scanned and cause backend worker stalls.

---

## 3. Quantitative Security Limits & Constraints

All archive processing must enforce the following immutable thresholds:

| Constraint | Config Key | Default Limit | Maximum Permissible | Rationale |
|---|---|---|---|---|
| **Max Upload Archive Size** | `MAX_UPLOAD_SIZE` | 100 MB (104,857,600 bytes) | 100 MB | Bounds inbound network transfer and initial file buffering on disk. |
| **Max Archive Entry Count** | `MAX_ARCHIVE_ENTRIES` | 5,000 entries | 10,000 entries | Prevents inode exhaustion and unbounded loop processing in extraction workers. |
| **Max Total Uncompressed Size** | `MAX_UNCOMPRESSED_SIZE` | 250 MB | 500 MB | Prevents disk filling on host temporary storage. |
| **Max Compression Ratio** | `MAX_COMPRESSION_RATIO` | 100:1 | 100:1 | Detects and aborts zip bomb decompression attempts before writing to disk. |
| **Max Single File Size** | `MAX_SINGLE_FILE_SIZE` | 10 MB | 25 MB | Prevents single massive source files from degrading AST parsers. |

*Rule:* If any single limit is exceeded during pre-extraction inspection, the extraction must be aborted immediately, the temporary upload deleted, and an informative error returned.

---

## 4. Path Validation & Zip Slip Prevention

### 4.1 Strict Canonical Path Boundary Verification
Every member path inside the archive must be verified against the target extraction directory using canonical path resolution before being written to disk:

```python
# Required invariant for Dev B implementation in extraction_service.py:
def is_safe_path(target_directory: str, member_path: str) -> bool:
    target_abs = os.path.abspath(target_directory)
    # Resolve target destination path
    dest_path = os.path.abspath(os.path.join(target_abs, member_path))
    # Assert that dest_path is strictly contained within target_abs
    return os.path.commonpath([target_abs, dest_path]) == target_abs
```

### 4.2 Prohibited Path Patterns
The extractor must immediately reject the archive if any member path satisfies any of the following:
- Contains directory traversal sequences: `..` or `.` components that attempt to escape the root.
- Starts with an absolute root slash: `/` or `\` (POSIX or Windows).
- Contains a Windows drive specification: e.g., `C:`, `D:`.
- Contains null bytes (`\0`) or control characters.

---

## 5. Symbolic Links & Hard Links Policy

- **Strict Prohibition:** Thread Trace **strictly disallows** symbolic links and hard links inside uploaded archives.
- **Detection Mechanism:**
  - Before extracting any entry, inspect `ZipInfo.external_attr`.
  - In Unix file modes, symbolic links are identified by the `S_IFLNK` bit flag (`(external_attr >> 16) & 0o170000 == 0o120000`).
- **Action:** If a symbolic link or hard link is detected:
  - Option A (Default): Reject the entire archive with a `SECURITY_ERROR: Symbolic links are prohibited`.
  - Option B: Drop/skip the entry entirely and record an audit log warning.
- Under no circumstances may a symbolic link be written to disk or followed.

---

## 6. Duplicate Entry Handling

- **Threat:** An archive containing two entries for `app/main.py`. The first file could be clean, while the second overwrites it with malicious code, bypassing naive inspection.
- **Policy:** The extractor must track every normalized destination path in a set during inspection. If a duplicate destination path is encountered:
  - Reject the archive with `INVALID_ARCHIVE: Duplicate entry detected for path '<path>'`.
  - Do not allow sequential overwrites of extracted files.

---

## 7. Corrupt & Invalid Archive Handling

The extraction service must safely intercept and handle corrupted or abnormal archive states:
1. **Invalid Magic Bytes:** Reject files not beginning with standard ZIP signatures (`PK\x03\x04`).
2. **Encrypted / Password-Protected Archives:**
   - Detect `flag_bits & 0x1` (encryption flag in `ZipInfo`).
   - Immediately reject with `ENCRYPTED_ARCHIVE_NOT_SUPPORTED: Password-protected ZIP archives cannot be scanned`.
3. **Corrupt CRC / Truncated Streams:**
   - Wrap decompression in standard error traps (`zipfile.BadZipFile`, `zlib.error`, `EOFError`).
   - Clean up partially extracted files immediately upon exception.

---

## 8. Temporary Extraction Directories & Permissions

1. **Isolation:**
   - Each upload is extracted into a dedicated, unique directory:
     `/tmp/thread-trace/workspaces/<scan_id>/`
   - Where `<scan_id>` is a cryptographically random UUIDv4.
2. **Filesystem Permissions:**
   - Created with POSIX permissions `0700` (`rwx------`), restricting read, write, and execute permissions exclusively to the application service process.
   - Files extracted inside receive permissions `0600` (`rw-------`) or `0700` for subdirectories. World-writable permissions (`0777`) must never be granted.

---

## 9. Safe Cleanup Lifecycle

1. **Deterministic Post-Scan Cleanup:**
   - Both the uploaded raw archive (`/tmp/thread-trace/uploads/<scan_id>.zip`) and the extracted workspace (`/tmp/thread-trace/workspaces/<scan_id>/`) must be deleted inside a mandatory Python `finally:` block in `scan_service.py`.
2. **Resilience to Crashes (Orphan Cleanup):**
   - An asynchronous background cleaner utility periodically inspects `/tmp/thread-trace/workspaces/` and purges any directory whose creation timestamp exceeds the maximum scan lifecycle (30 minutes).

---

## 10. Division of Responsibilities (Dev C vs. Dev B)

To maintain clean architecture and prevent conflicts across developer ownership:

### Dev C Responsibilities (Cybersecurity, Scanner Integration & DevOps):
1. **Authoritative Specification:** Define the quantitative limits, threat model, and validation criteria (this document).
2. **Security Test Fixtures:** Author synthetic test fixtures in Phase 5 containing:
   - Malicious Zip Slip test archives (`test_zip_slip.zip`).
   - Zip bomb / high-ratio test archives (`test_zip_bomb.zip`).
   - Symlink traversal test archives (`test_symlink.zip`).
   - Corrupt / encrypted archive test files (`test_corrupt.zip`).
3. **Security Verification Tests:** Write automated tests (`tests/` and `backend/tests/`) verifying that the extraction pipeline rigorously blocks these attack vectors.

### Dev B Responsibilities (Backend Developer):
1. **Implementation Ownership:** Implement the validation logic and extraction routines in `backend/app/services/extraction_service.py` and `backend/app/utils/file_utils.py` adhering to this specification.
2. **FastAPI Upload Endpoint:** Handle multipart form upload streaming, file size verification, and dispatch to `extraction_service.py`.
3. **API Error Responses:** Map extraction exceptions to clean HTTP 400 Bad Request error responses with structured JSON error details.
4. **Cleanup Invocation:** Ensure `extraction_service.cleanup_workspace(workspace_dir)` is called in orchestration workflows.
