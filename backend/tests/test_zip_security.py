"""Tests for ZIP archive security boundaries and abuse defenses.

Validates:
- Zip Slip path traversal defenses (relative and absolute paths)
- Zip bomb limits (compression ratio > 100:1, uncompressed > 250 MB)
- Excessive file entry count (> 5,000 entries)
- Symlink traversal defenses
- Duplicate member name detection
- Corrupted and non-ZIP byte handling
- Safe valid archive extraction validation
"""

from __future__ import annotations

import io
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

# Constants aligned with specs/ZIP_ARCHIVE_SECURITY_SPEC.md
MAX_UPLOAD_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_UNCOMPRESSED_SIZE_BYTES = 250 * 1024 * 1024  # 250 MB
MAX_ENTRY_COUNT = 5000
MAX_COMPRESSION_RATIO = 100.0


class ZipSecurityValidationError(Exception):
    """Raised when an uploaded ZIP archive violates security constraints."""


def validate_zip_archive_security(
    zip_bytes: bytes,
    max_upload_size: int = MAX_UPLOAD_SIZE_BYTES,
    max_uncompressed_size: int = MAX_UNCOMPRESSED_SIZE_BYTES,
    max_entries: int = MAX_ENTRY_COUNT,
    max_ratio: float = MAX_COMPRESSION_RATIO,
) -> list[str]:
    """
    Validate ZIP archive safety against DoS, Zip Slip, and archive abuse.

    Returns:
        list[str]: Normalized entry names if valid.

    Raises:
        ZipSecurityValidationError: If any security constraint is violated.
    """
    if len(zip_bytes) > max_upload_size:
        raise ZipSecurityValidationError(
            f"Archive size ({len(zip_bytes)} bytes) exceeds maximum limit ({max_upload_size} bytes)."
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception as exc:
        raise ZipSecurityValidationError(f"Invalid or corrupted ZIP archive: {exc}") from exc

    infolist = zf.infolist()

    if len(infolist) > max_entries:
        raise ZipSecurityValidationError(
            f"Archive contains {len(infolist)} entries, exceeding maximum permitted ({max_entries})."
        )

    total_uncompressed = 0
    seen_names: set[str] = set()
    validated_names: list[str] = []

    for info in infolist:
        name = info.filename

        # Detect Zip Slip: directory traversal via ..
        norm_name = name.replace("\\", "/")
        parts = [p for p in norm_name.split("/") if p and p != "."]

        if ".." in parts:
            raise ZipSecurityValidationError(
                f"Zip Slip detected: member path '{name}' contains directory traversal '..'."
            )

        # Detect absolute paths
        if norm_name.startswith("/") or (len(name) >= 2 and name[1] == ":"):
            raise ZipSecurityValidationError(
                f"Absolute path traversal detected: member path '{name}' is absolute."
            )

        # Detect duplicate names
        if norm_name in seen_names:
            raise ZipSecurityValidationError(
                f"Duplicate archive entry detected: '{norm_name}'."
            )
        seen_names.add(norm_name)

        # Detect symlinks pointing outside
        # In Unix ZIPs, high 16 bits of external_attr store file mode; 0o120000 is S_IFLNK
        is_symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
        if is_symlink:
            raise ZipSecurityValidationError(
                f"Symlink member detected: '{name}'. Symlinks are prohibited."
            )

        total_uncompressed += info.file_size
        if total_uncompressed > max_uncompressed_size:
            raise ZipSecurityValidationError(
                f"Total uncompressed size ({total_uncompressed} bytes) exceeds limit ({max_uncompressed_size} bytes)."
            )

        validated_names.append(norm_name)

    # Check overall compression ratio
    compressed_size = len(zip_bytes)
    if compressed_size > 0:
        ratio = total_uncompressed / compressed_size
        if ratio > max_ratio and total_uncompressed > 1024 * 1024:
            raise ZipSecurityValidationError(
                f"Compression ratio bomb detected: ratio {ratio:.1f}:1 exceeds limit {max_ratio}:1."
            )

    return validated_names


class TestZipSecurityDefenses:
    """Test suite verifying all archive security requirements from Task 5.4."""

    def test_clean_valid_zip_passes(self) -> None:
        """Verify normal compliant ZIP archive passes security checks."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("src/main.py", "print('hello world')\n")
            zf.writestr("src/utils.py", "def helper(): pass\n")
            zf.writestr("README.md", "# Sample App\n")

        valid_names = validate_zip_archive_security(buf.getvalue())
        assert len(valid_names) == 3
        assert "src/main.py" in valid_names

    def test_zip_slip_relative_path_rejected(self) -> None:
        """Verify archive entries containing '../' traversal are rejected."""
        traversal_paths = [
            "../../evil.py",
            "app/../../../etc/shadow",
            "safe/../../outside.py",
            "foo/bar/../../../../secret.txt",
        ]

        for bad_path in traversal_paths:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr(bad_path, "malicious payload")

            with pytest.raises(ZipSecurityValidationError, match="Zip Slip detected"):
                validate_zip_archive_security(buf.getvalue())

    def test_zip_absolute_path_rejected(self) -> None:
        """Verify archive entries with absolute paths are rejected."""
        absolute_paths = [
            "/etc/passwd",
            "/var/www/index.html",
            "C:\\Windows\\System32\\calc.exe",
        ]

        for bad_path in absolute_paths:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr(bad_path, "malicious payload")

            with pytest.raises(ZipSecurityValidationError, match="Absolute path traversal"):
                validate_zip_archive_security(buf.getvalue())

    def test_zip_excessive_entries_rejected(self) -> None:
        """Verify archive containing > 5,000 entries is rejected to prevent inode exhaustion."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(5001):
                zf.writestr(f"file_{i}.txt", "x")

        with pytest.raises(ZipSecurityValidationError, match="exceeding maximum permitted"):
            validate_zip_archive_security(buf.getvalue(), max_entries=5000)

    def test_zip_oversized_uncompressed_rejected(self) -> None:
        """Verify archive exceeding 250 MB uncompressed is rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # Create a 2MB dummy file with low max_uncompressed limit for testing
            zf.writestr("large.dat", b"A" * (2 * 1024 * 1024))

        with pytest.raises(ZipSecurityValidationError, match="Total uncompressed size"):
            validate_zip_archive_security(
                buf.getvalue(),
                max_uncompressed_size=1 * 1024 * 1024,  # 1MB limit for test
            )

    def test_zip_compression_ratio_bomb_rejected(self) -> None:
        """Verify high-ratio compression bombs are rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # 5MB of zeros compresses to ~5KB (ratio > 1000:1)
            zf.writestr("zeroes.bin", b"\x00" * (5 * 1024 * 1024))

        with pytest.raises(ZipSecurityValidationError, match="Compression ratio bomb detected"):
            validate_zip_archive_security(buf.getvalue(), max_ratio=50.0)

    def test_zip_duplicate_entries_detected(self) -> None:
        """Verify archives with duplicate filenames are rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("config.py", "x = 1")
            zf.writestr("config.py", "x = 2")

        with pytest.raises(ZipSecurityValidationError, match="Duplicate archive entry detected"):
            validate_zip_archive_security(buf.getvalue())

    def test_zip_symlink_prohibited(self) -> None:
        """Verify symlink archive entries are rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zinfo = zipfile.ZipInfo("symlink_to_passwd")
            zinfo.create_system = 3  # Unix
            # 0o120777: S_IFLNK with 0777 permissions
            zinfo.external_attr = 0o120777 << 16
            zf.writestr(zinfo, "/etc/passwd")

        with pytest.raises(ZipSecurityValidationError, match="Symlink member detected"):
            validate_zip_archive_security(buf.getvalue())

    def test_invalid_corrupted_zip_bytes_rejected(self) -> None:
        """Verify corrupted bytes or non-ZIP headers are safely rejected."""
        corrupted_payloads = [
            b"",
            b"NOT_A_ZIP_HEADER_DATA_STREAM",
            b"PK\x03\x04truncated_incomplete_header",
        ]

        for payload in corrupted_payloads:
            with pytest.raises(ZipSecurityValidationError, match="Invalid or corrupted ZIP archive"):
                validate_zip_archive_security(payload)
