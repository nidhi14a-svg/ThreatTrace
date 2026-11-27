import asyncio
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any

from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult


class DependencyScanner(BaseScanner):
    """
    Dependency vulnerability scanner adapter for Thread Trace.

    Integrates OSV-Scanner (Open Source Vulnerabilities) for Software Composition
    Analysis (SCA) across application dependency manifests and lockfiles (Python,
    Node.js, Go, Rust, Java, etc.). Operates in non-privileged recursive scan mode,
    captures structured JSON advisory reports, normalizes severity from CVSS v3
    metrics, derives confidence based on manifest determinism (lockfile vs manifest),
    sanitizes manifest file paths against directory traversal, and maps OSV-Scanner
    exit codes to the shared ScannerExecutionResult contract.
    """

    name: str = "dependency"

    IGNORED_DIRS: set[str] = {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".eggs",
        "dist",
        "build",
    }

    KNOWN_EXACT_MANIFESTS: set[str] = {
        "requirements.txt",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "pyproject.toml",
        "setup.py",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gemfile",
        "gemfile.lock",
        "composer.json",
        "composer.lock",
    }

    LOCKFILE_NAMES: set[str] = {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pipfile.lock",
        "poetry.lock",
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "go.sum",
    }

    def __init__(
        self,
        binary_path: str = "osv-scanner",
        timeout_seconds: float = 60.0,
        max_output_bytes: int = 10 * 1024 * 1024,
        allow_skip_if_missing: bool = False,
        offline: bool = True,
    ) -> None:
        """
        Initialize DependencyScanner with configurable execution parameters.

        Args:
            binary_path: Executable name or absolute path for OSV-Scanner.
            timeout_seconds: Hard timeout in seconds for subprocess execution.
            max_output_bytes: Maximum buffer size for stdout/stderr in bytes (default 10MB).
            allow_skip_if_missing: If True, mark missing binary as 'skipped' instead of 'failed'.
            offline: If True, pass --offline flag to OSV-Scanner to use cached DB.
        """
        self.binary_path = os.environ.get("OSV_SCANNER_BINARY_PATH", binary_path)
        self.timeout_seconds = float(
            os.environ.get("OSV_SCANNER_TIMEOUT_SECONDS", str(timeout_seconds))
        )
        self.max_output_bytes = int(
            os.environ.get("OSV_SCANNER_MAX_OUTPUT_BYTES", str(max_output_bytes))
        )
        self.allow_skip_if_missing = allow_skip_if_missing
        offline_env = os.environ.get("OSV_SCANNER_OFFLINE", str(offline)).lower()
        self.offline = offline_env in ("true", "1", "yes")

    def is_available(self) -> bool:
        """Check if the OSV-Scanner executable is available on PATH."""
        return shutil.which(self.binary_path) is not None

    def _has_manifest_files(self, workspace_path: Path) -> bool:
        """
        Quickly inspect workspace directory to check for presence of supported manifests.
        Avoids descending into excluded directories such as .git or node_modules.
        """
        try:
            for root, dirs, files in os.walk(workspace_path):
                dirs[:] = [d for d in dirs if d not in self.IGNORED_DIRS]
                for file in files:
                    lower_file = file.lower()
                    if lower_file in self.KNOWN_EXACT_MANIFESTS:
                        return True
                    if lower_file.startswith("requirements") and lower_file.endswith(".txt"):
                        return True
                    if lower_file.endswith(".lock"):
                        return True
            return False
        except (PermissionError, OSError):
            return False

    def _sanitize_path(self, raw_path: str, workspace_path: Path) -> str:
        """
        Sanitize manifest path and verify it stays within workspace boundaries.
        Returns a normalized relative POSIX path, or '[REJECTED_OUTSIDE_WORKSPACE]'.
        """
        if not raw_path:
            return "[UNKNOWN_MANIFEST]"

        try:
            p = Path(raw_path)
            ws_resolved = workspace_path.resolve()

            if p.is_absolute():
                resolved = p.resolve()
            else:
                resolved = (workspace_path / p).resolve()

            try:
                rel = resolved.relative_to(ws_resolved)
                norm = rel.as_posix()
                if norm == ".":
                    return p.name
                return norm
            except ValueError:
                return "[REJECTED_OUTSIDE_WORKSPACE]"
        except Exception:
            return "[INVALID_PATH]"

    def _determine_confidence(self, manifest_path: str) -> str:
        """
        Determine detection confidence based on manifest determinism:
        - 'high' for exact lockfiles (resolved hashes and versions).
        - 'medium' for unpinned manifests or top-level project descriptors.
        """
        lower = Path(manifest_path).name.lower()
        if lower in self.LOCKFILE_NAMES or lower.endswith(".lock"):
            return "high"
        return "medium"

    def _extract_severity(self, vuln: dict[str, Any]) -> str:
        """
        Derive standardized severity ('critical', 'high', 'medium', 'low') from advisory metadata.
        Checks database_specific severity, CVSS scores, and vector strings before falling back.
        """
        # 1. Check database_specific / ecosystem_specific severity strings
        db_specific = vuln.get("database_specific")
        if isinstance(db_specific, dict):
            sev_str = db_specific.get("severity")
            if isinstance(sev_str, str):
                upper_sev = sev_str.strip().upper()
                if upper_sev == "CRITICAL":
                    return "critical"
                if upper_sev == "HIGH":
                    return "high"
                if upper_sev in ("MODERATE", "MEDIUM"):
                    return "medium"
                if upper_sev == "LOW":
                    return "low"

        eco_specific = vuln.get("ecosystem_specific")
        if isinstance(eco_specific, dict):
            sev_str = eco_specific.get("severity")
            if isinstance(sev_str, str):
                upper_sev = sev_str.strip().upper()
                if upper_sev == "CRITICAL":
                    return "critical"
                if upper_sev == "HIGH":
                    return "high"
                if upper_sev in ("MODERATE", "MEDIUM"):
                    return "medium"
                if upper_sev == "LOW":
                    return "low"

        # 2. Check CVSS numeric score in severity list
        severity_entries = vuln.get("severity")
        if isinstance(severity_entries, list):
            for entry in severity_entries:
                if isinstance(entry, dict):
                    score = entry.get("score")
                    if isinstance(score, (int, float)):
                        num = float(score)
                        if num >= 9.0:
                            return "critical"
                        if num >= 7.0:
                            return "high"
                        if num >= 4.0:
                            return "medium"
                        return "low"
                    if isinstance(score, str):
                        try:
                            num = float(score)
                            if num >= 9.0:
                                return "critical"
                            if num >= 7.0:
                                return "high"
                            if num >= 4.0:
                                return "medium"
                            return "low"
                        except ValueError:
                            # CVSS Vector String check
                            if "CVSS:3" in score or "CVSS:4" in score:
                                if "/C:H/I:H/A:H" in score and ("/AV:N" in score or "/PR:N" in score):
                                    return "critical"
                                if "/C:H" in score or "/I:H" in score:
                                    return "high"

        return "medium"

    def _extract_fixed_versions(self, vuln: dict[str, Any]) -> list[str]:
        """Extract unique fixed versions from advisory affected ranges."""
        fixed: list[str] = []
        affected = vuln.get("affected")
        if isinstance(affected, list):
            for aff in affected:
                if isinstance(aff, dict):
                    ranges = aff.get("ranges")
                    if isinstance(ranges, list):
                        for r in ranges:
                            if isinstance(r, dict):
                                events = r.get("events")
                                if isinstance(events, list):
                                    for event in events:
                                        if isinstance(event, dict) and "fixed" in event:
                                            fixed.append(str(event["fixed"]))
        return list(dict.fromkeys(fixed))

    def _build_evidence(
        self,
        pkg_name: str,
        pkg_version: str,
        manifest_path: str,
        vuln_id: str,
        title: str,
        fixed_versions: list[str],
    ) -> str:
        """Construct bounded, human-readable evidence context for the finding."""
        parts = [
            f"Dependency '{pkg_name}' version '{pkg_version}' in '{manifest_path}' matches advisory '{vuln_id}'"
        ]
        if title and title != vuln_id:
            parts.append(f"({title})")
        if fixed_versions:
            parts.append(f"Fixed in: {', '.join(fixed_versions)}")

        evidence = " ".join(parts)
        if len(evidence) > 1000:
            evidence = evidence[:997] + "..."
        return evidence

    async def scan(self, workspace: str) -> ScannerExecutionResult:
        """
        Execute OSV-Scanner against dependency manifests in an isolated workspace.

        Args:
            workspace: Absolute path to the isolated directory containing extracted target code.

        Returns:
            ScannerExecutionResult: Structured result containing raw findings, status, duration, and error.
        """
        start_time = time.monotonic()

        # 1. Workspace Validation
        if not workspace or not str(workspace).strip():
            return self.create_result(
                status="failed",
                duration_seconds=0.0,
                error="Workspace path is required and cannot be empty.",
            )

        workspace_path = Path(workspace).resolve()

        if not workspace_path.exists():
            return self.create_result(
                status="skipped",
                findings=[],
                duration_seconds=0.0,
                error=None,
            )

        if not workspace_path.is_dir():
            return self.create_result(
                status="failed",
                duration_seconds=0.0,
                error=f"Workspace path is not a directory: '{workspace}'",
            )

        # 2. Check for empty workspace
        try:
            has_files = any(workspace_path.iterdir())
        except (PermissionError, OSError) as exc:
            return self.create_result(
                status="failed",
                duration_seconds=time.monotonic() - start_time,
                error=f"Cannot access workspace directory: {exc}",
            )

        if not has_files:
            return self.create_result(
                status="skipped",
                findings=[],
                duration_seconds=time.monotonic() - start_time,
                error=None,
            )

        # 3. Check for supported dependency manifests
        if not self._has_manifest_files(workspace_path):
            return self.create_result(
                status="skipped",
                findings=[],
                duration_seconds=time.monotonic() - start_time,
                error=None,
            )

        # 4. Binary Availability Check
        if not self.is_available():
            duration = time.monotonic() - start_time
            if self.allow_skip_if_missing:
                return self.create_result(
                    status="skipped",
                    findings=[],
                    duration_seconds=duration,
                    error=None,
                )
            return self.create_result(
                status="failed",
                duration_seconds=duration,
                error=(
                    f"OSV-Scanner executable '{self.binary_path}' not found on PATH. "
                    "Ensure OSV-Scanner is installed or enable allow_skip_if_missing."
                ),
            )

        # 5. Build Command Arguments
        cmd = [
            self.binary_path,
            "--json",
            "--no-ignore",
            "-r",
        ]
        if self.offline:
            cmd.extend([
                "--offline",
                "--offline-vulnerabilities",
                "--local-db-path",
                "/app/osv-db",
            ])
        cmd.append(str(workspace_path))

        # 6. Execute Subprocess Asynchronously
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout_seconds,
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                return self.create_result(
                    status="failed",
                    duration_seconds=time.monotonic() - start_time,
                    error=f"OSV-Scanner execution timed out after {self.timeout_seconds} seconds.",
                )

        except FileNotFoundError:
            duration = time.monotonic() - start_time
            if self.allow_skip_if_missing:
                return self.create_result(
                    status="skipped",
                    findings=[],
                    duration_seconds=duration,
                    error=None,
                )
            return self.create_result(
                status="failed",
                duration_seconds=duration,
                error=f"OSV-Scanner executable '{self.binary_path}' could not be executed.",
            )
        except Exception as exc:
            return self.create_result(
                status="failed",
                duration_seconds=time.monotonic() - start_time,
                error=f"Failed to execute OSV-Scanner subprocess: {exc}",
            )

        # 7. Bound Output Streams
        stdout_bytes = (stdout_bytes or b"")[: self.max_output_bytes]
        stderr_bytes = (stderr_bytes or b"")[: self.max_output_bytes]

        stdout_str = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()

        # 8. Parse Output JSON
        parsed_data: dict[str, Any] = {}
        if stdout_str:
            try:
                parsed_data = json.loads(stdout_str)
            except json.JSONDecodeError:
                # Some OSV-Scanner versions may output informational text before JSON
                json_start = stdout_str.find("{")
                json_end = stdout_str.rfind("}")
                if json_start != -1 and json_end != -1 and json_end > json_start:
                    try:
                        parsed_data = json.loads(stdout_str[json_start : json_end + 1])
                    except json.JSONDecodeError:
                        parsed_data = {}

        if not parsed_data and stderr_str:
            try:
                parsed_data = json.loads(stderr_str)
            except json.JSONDecodeError:
                pass

        # 9. Handle Exit Codes & Malformed Output
        returncode = proc.returncode

        if not parsed_data:
            duration = time.monotonic() - start_time
            if returncode == 0:
                # Clean scan with no findings
                return self.create_result(
                    status="success",
                    findings=[],
                    duration_seconds=duration,
                    error=None,
                )
            # Failure with non-zero exit code and unparseable output
            error_msg = stderr_str or f"OSV-Scanner exited with code {returncode} and produced unparseable output."
            sanitized_error = error_msg[:1000]
            return self.create_result(
                status="failed",
                duration_seconds=duration,
                error=sanitized_error,
            )

        # 10. Extract and Normalize Findings
        raw_findings: list[dict[str, Any]] = []
        results = parsed_data.get("results")

        if isinstance(results, list):
            for res in results:
                if not isinstance(res, dict):
                    continue

                source = res.get("source")
                raw_manifest = ""
                if isinstance(source, dict):
                    raw_manifest = source.get("path", "")
                elif isinstance(source, str):
                    raw_manifest = source

                rel_manifest = self._sanitize_path(raw_manifest, workspace_path)
                confidence = self._determine_confidence(rel_manifest)

                packages = res.get("packages")
                if isinstance(packages, list):
                    for pkg_item in packages:
                        if not isinstance(pkg_item, dict):
                            continue

                        pkg_info = pkg_item.get("package") or {}
                        pkg_name = pkg_info.get("name", "unknown")
                        pkg_version = pkg_info.get("version", "unknown")
                        pkg_ecosystem = pkg_info.get("ecosystem", "unknown")

                        vulnerabilities = pkg_item.get("vulnerabilities")
                        if isinstance(vulnerabilities, list):
                            for vuln in vulnerabilities:
                                if not isinstance(vuln, dict):
                                    continue

                                vuln_id = vuln.get("id", "UNKNOWN-VULN")
                                summary = vuln.get("summary") or ""
                                details = vuln.get("details") or ""

                                if summary:
                                    title = summary
                                elif details:
                                    title = details.split("\n")[0].strip()
                                else:
                                    title = f"Vulnerability in {pkg_name} {pkg_version}"

                                aliases = vuln.get("aliases") or []
                                fixed_versions = self._extract_fixed_versions(vuln)
                                severity = self._extract_severity(vuln)
                                evidence = self._build_evidence(
                                    pkg_name,
                                    pkg_version,
                                    rel_manifest,
                                    vuln_id,
                                    title,
                                    fixed_versions,
                                )

                                finding_dict: dict[str, Any] = {
                                    "scanner_name": self.name,
                                    "rule_id": vuln_id,
                                    "title": title,
                                    "severity": severity,
                                    "file": rel_manifest,
                                    "line": None,
                                    "evidence": evidence,
                                    "confidence": confidence,
                                    "raw_category": "dependency_vulnerability",
                                    "package_name": pkg_name,
                                    "package_version": pkg_version,
                                    "package_ecosystem": pkg_ecosystem,
                                    "aliases": aliases,
                                    "fixed_versions": fixed_versions,
                                    "advisory_url": f"https://osv.dev/vulnerability/{vuln_id}",
                                    "details": details[:1000] if details else None,
                                    "database_specific": vuln.get("database_specific"),
                                }
                                raw_findings.append(finding_dict)

        duration = time.monotonic() - start_time

        # OSV-Scanner return code 1 indicates vulnerabilities were found.
        # Return code 0 indicates clean scan.
        # If return code is non-zero but findings were parsed successfully, mark success/partial.
        if returncode in (0, 1):
            status = "success"
        else:
            status = "partial" if raw_findings else "failed"

        error_desc: str | None = None
        if status != "success" and stderr_str:
            error_desc = stderr_str[:1000]

        return self.create_result(
            status=status,
            findings=raw_findings,
            duration_seconds=duration,
            error=error_desc,
        )
