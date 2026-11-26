# Dependency Scanner Integration Specification (OSV-Scanner)

**File:** `specs/DEPENDENCY_SCANNER_INTEGRATION_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Target:** `backend/app/scanners/dependency_scanner.py`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Task 2.5)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

This specification defines the architectural integration, execution boundary, output normalization, and error handling for the **Dependency Scanner** (`DependencyScanner`) in Thread Trace.

The dependency scanner is driven by **OSV-Scanner** (Google Open Source Vulnerabilities Scanner), providing Software Composition Analysis (SCA) to detect known Common Vulnerabilities and Exposures (CVEs) and GitHub Security Advisories (GHSAs) across application dependency manifests and lockfiles.

### 1.1 Core Responsibilities
1. **Target Identification:** Automatically identify supported dependency manifests and lockfiles within an isolated workspace.
2. **Subprocess Isolation:** Execute `osv-scanner` asynchronously with strict parameter separation (`shell=False`), timeout enforcement, and memory-bounded output streams.
3. **Deterministic Output Normalization:** Parse OSV-Scanner hierarchical JSON output into flat raw finding dictionaries conforming to the `ScannerExecutionResult.findings` contract.
4. **Severity & Confidence Mapping:** Accurately derive severity ratings from CVSS v3 metrics or advisory databases, and differentiate confidence between deterministic lockfiles (`high`) and loose manifests (`medium`).
5. **Path Traversal Protection:** Sanitize manifest paths, strictly preventing exposure of host directories outside the isolated workspace.
6. **Graceful Degradation:** Safely handle workspaces without manifests, clean workspaces with zero vulnerabilities, tool timeouts, and missing executables.

---

## 2. Cybersecurity Domain Alignment

The `DependencyScanner` operates exclusively within the **Dependency & Configuration Security** domain:
- **Primary Domain:** `dependencies` (strict domain approved by Dev B).
- **Raw Category:** `dependency_vulnerability`.
- **Target Flaws:**
  - Outdated libraries with known public exploits (CVEs / GHSAs).
  - High-impact supply-chain vulnerabilities (e.g., remote code execution in transitive parser packages).
  - Insecure transitive dependencies pulled via top-level manifests.

---

## 3. Supported Dependency Manifests & Package Ecosystems

The scanner scans workspaces for supported lockfiles and manifests as defined in `specs/SCANNER_LANGUAGE_SUPPORT_SPEC.md`:

| Ecosystem | Deterministic Lockfiles (`confidence: high`) | Unpinned Manifests (`confidence: medium`) |
|---|---|---|
| **Python** | `Pipfile.lock`, `poetry.lock` | `requirements.txt`, `requirements-*.txt`, `Pipfile`, `pyproject.toml`, `setup.py` |
| **Node.js / JS / TS** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `package.json` |
| **Go** | `go.sum` | `go.mod` |
| **Rust** | `Cargo.lock` | `Cargo.toml` |
| **Java** | — | `pom.xml`, `build.gradle` |
| **Ruby** | `Gemfile.lock` | `Gemfile` |
| **PHP** | `composer.lock` | `composer.json` |

### 3.1 Pre-Scan Workspace Filter (`_has_manifest_files`)
To avoid unnecessary subprocess overhead, `DependencyScanner` executes a fast directory inspection:
- If no supported manifest or lockfile is found in the workspace, the scan is immediately marked as `status: "skipped"` with `error: None` and `findings: []`.
- This mirrors the language-specific skipping behavior established in `BanditScanner`.

---

## 4. Execution Boundary & Subprocess Security

### 4.1 Invocation Contract
The scanner adapter executes OSV-Scanner via Python's asynchronous subprocess API:
```python
cmd = [
    self.binary_path,
    "--json",
    "-r",
    str(workspace_path),
]
if self.offline:
    cmd.append("--offline")
```

### 4.2 Security Constraints
1. **No Shell Execution:** `shell=False` is strictly required. Arguments are passed as an immutable list of strings.
2. **Execution Isolation:** OSV-Scanner is run against the isolated extraction workspace directory. No source code or build scripts from the repository are executed.
3. **Execution Timeout:** Default hard timeout of 60.0 seconds (configurable via `OSV_SCANNER_TIMEOUT_SECONDS`).
4. **Memory Bounding:** Maximum stdout/stderr buffer size of 10 MB (configurable via `OSV_SCANNER_MAX_OUTPUT_BYTES`) to prevent denial-of-service from massive vulnerability reports.
5. **No Write Access:** OSV-Scanner operates in read-only analysis mode on the workspace files.

---

## 5. Exit Code Semantics

OSV-Scanner returns specific process exit codes that must be mapped to `ScannerExecutionResult.status`:

| Exit Code | OSV-Scanner Meaning | Thread Trace Status | Action |
|---|---|---|---|
| **0** | No vulnerabilities discovered | `success` | Parse output, return empty findings list (`[]`). |
| **1** | Vulnerabilities discovered | `success` / `partial` | Parse JSON findings. If valid findings are parsed, status is `success` (or `partial` if warning banners exist). |
| **>= 2** | Fatal execution error, invalid flags, network failure | `failed` | Capture sanitized error string. If unparseable output, report failure. |

---

## 6. OSV-Scanner JSON Parsing & Normalization

### 6.1 OSV-Scanner Raw Output Schema
OSV-Scanner returns a hierarchical JSON document:
```json
{
  "results": [
    {
      "source": {
        "path": "/workspace/requirements.txt",
        "type": "lockfile"
      },
      "packages": [
        {
          "package": {
            "name": "jinja2",
            "version": "2.11.2",
            "ecosystem": "PyPI"
          },
          "vulnerabilities": [
            {
              "id": "GHSA-g3rq-g295-4838",
              "summary": "Jinja2 vulnerable to ReDoS",
              "details": "In Jinja2 before 2.11.3, an attacker can cause a denial of service...",
              "aliases": ["CVE-2020-28493"],
              "severity": [
                {
                  "type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                }
              ],
              "affected": [
                {
                  "ranges": [
                    {
                      "type": "ECOSYSTEM",
                      "events": [{"introduced": "0"}, {"fixed": "2.11.3"}]
                    }
                  ]
                }
              ],
              "database_specific": {
                "severity": "HIGH"
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### 6.2 Raw Finding Normalization Structure
Each detected vulnerability is flattened into a raw dictionary conforming to:

```python
{
    "scanner_name": "dependency",
    "rule_id": "GHSA-g3rq-g295-4838",
    "title": "Jinja2 vulnerable to ReDoS",
    "severity": "high",
    "file": "requirements.txt",
    "line": None,
    "evidence": "Dependency 'jinja2' version '2.11.2' in 'requirements.txt' matches advisory 'GHSA-g3rq-g295-4838' (Jinja2 vulnerable to ReDoS). Fixed in: 2.11.3",
    "confidence": "medium",
    "raw_category": "dependency_vulnerability",
    "package_name": "jinja2",
    "package_version": "2.11.2",
    "package_ecosystem": "PyPI",
    "aliases": ["CVE-2020-28493"],
    "fixed_versions": ["2.11.3"],
    "advisory_url": "https://osv.dev/vulnerability/GHSA-g3rq-g295-4838",
    "details": "In Jinja2 before 2.11.3, an attacker can cause a denial of service..."
}
```

### 6.3 Severity Resolution Strategy
Severity is resolved through a fallback chain:
1. **Advisory Database Severity:** Check `database_specific.severity` (e.g., `"CRITICAL"`, `"HIGH"`, `"MODERATE"` / `"MEDIUM"`, `"LOW"`).
2. **Numeric CVSS Score:** If `severity[].score` is a decimal score:
   - `9.0 – 10.0` -> `"critical"`
   - `7.0 – 8.9` -> `"high"`
   - `4.0 – 6.9` -> `"medium"`
   - `0.1 – 3.9` -> `"low"`
3. **CVSS Vector String:** Parse metrics from CVSS v3 vector string (e.g., `CVSS:3.1/...`).
4. **Default Fallback:** Default to `"medium"` for unrated dependencies.

### 6.4 Confidence Resolution Strategy
- **`high`:** Discovered via deterministic lockfile with exact version resolution (`.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.sum`).
- **`medium`:** Discovered via unpinned or top-level manifest (`requirements.txt`, `package.json`, `pyproject.toml`, etc.).

### 6.5 Evidence Generation & Bounding
Because dependency scanners operate on manifest files without highlighting code AST nodes, `DependencyScanner` synthesizes a deterministic, bounded evidence string:
- Format: `"Dependency '{name}' version '{version}' in '{file}' matches advisory '{id}' ({summary}). Fixed in: {fixed_versions}"`
- Length limit: Truncated to a maximum of 1,000 characters.
- Redaction: Sanitized against sensitive token leaks before storage.

---

## 7. Path Traversal & File System Safety

1. Manifest paths extracted from `source.path` must be resolved relative to the target `workspace_path`.
2. Any path containing `..` or attempting to resolve outside `workspace_path` is immediately rejected and mapped to `"[REJECTED_OUTSIDE_WORKSPACE]"`.
3. Backslashes are normalized to forward slashes (`/`), and leading slashes are stripped.

---

## 8. Cross-Developer Interfaces (Dev B Alignment)

- `DependencyScanner` yields `ScannerExecutionResult.findings` as a list of raw dictionaries.
- Dev B's backend is responsible for instantiating the Pydantic `Finding` model:
  - `domain`: Set to `"dependencies"`.
  - `tool`: Set to `"osv-scanner"`.
  - `line`: Set to `None`.
  - `raw_category`: Preserved as `"dependency_vulnerability"`.
- Dev C maintains 100% decoupling from FastAPI routes and MongoDB collections.
