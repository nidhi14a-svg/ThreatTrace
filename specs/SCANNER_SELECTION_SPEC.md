# Scanner Selection Specification

- **Document:** `specs/SCANNER_SELECTION_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Status:** Approved Specification (Phase 1)
- **Version:** 1.0.0

---

## 1. Executive Summary & Selection Architecture

Thread Trace employs a multi-scanner architecture to achieve comprehensive, high-fidelity security coverage across the five canonical cybersecurity domains. Rather than relying on a single monolithic scanner, Thread Trace combines specialized, best-in-class open-source static analysis security testing (SAST) and software composition analysis (SCA) engines.

The selected toolchain comprises:
1. **Semgrep:** Fast, multi-language semantic AST pattern matching and taint tracking engine.
2. **Bandit:** Dedicated Python AST security linter.
3. **Gitleaks:** Specialized regex and Shannon-entropy secret detection engine (with detect-secrets as secondary baseline alternative).
4. **OSV-Scanner:** Google’s official vulnerability scanner for open-source dependency lockfiles and manifests.
5. **Custom Security Rules:** Project-tailored rules and policies extending tool coverage to specific domain gaps.

*Phase 1 Rule:* Tools are documented and specified in Phase 1; installation and execution occur in Phase 2 and Phase 4.

---

## 2. Scanner 1: Semgrep

### 2.1 Purpose & Detection Capabilities
Semgrep is a fast, open-source static analysis engine that enforces rules based on Abstract Syntax Tree (AST) patterns rather than simple regex. It understands language syntax, variable assignments, imports, and function calls. In Thread Trace, Semgrep serves as the primary engine for Web Application Security and multi-language policy enforcement.

### 2.2 Cybersecurity Domains Supported
- **Web Application Security (Primary):** Detects OWASP Top 10 flaws including SQL Injection, Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), Path Traversal, and Command Injection.
- **Authentication & Access Control:** Detects missing auth decorators, JWT misconfigurations, insecure cookie parameters, and improper session setups.
- **Dependency & Configuration Security:** Detects misconfigurations in YAML/JSON configs and framework initialization flags (e.g., debug modes).
- **Network & Communication Security:** Identifies cleartext URLs and insecure client invocations.

### 2.3 Input Requirements & Flags
- **Target Input:** Directory path containing source code (e.g., `/workspace`).
- **Configuration Flags:**
  - `--config <rule_dir_or_pack>`: Path to local rule packs or standard rulesets (e.g., `p/owasp-top-ten`, `p/python`, `p/javascript`).
  - `--json`: Formats output to JSON for programmatic normalization.
  - `--metrics=off`: Disables outbound telemetry to external servers.
  - `--disable-version-check`: Prevents outbound network calls to check for updates.
  - `--max-target-bytes <bytes>`: Bounds maximum file size (default: 1 MB per file).
  - `--timeout <seconds>`: Per-file timeout (default: 10s per file).

### 2.4 Output Format & Parsing
Semgrep outputs a structured JSON document containing:
- `results`: Array of matches, each containing:
  - `check_id`: Rule identifier (e.g., `python.lang.security.injection.sql.sql-injection-format-string`).
  - `path`: Relative path to the scanned file.
  - `start` / `end`: Line and column numbers (`start.line`, `end.line`).
  - `extra.message`: Human-readable explanation and impact.
  - `extra.severity`: Semgrep severity level (`ERROR`, `WARNING`, `INFO`).
  - `extra.lines`: Extracted code snippet (raw evidence).
  - `extra.metadata`: Tags, CWE identifiers, OWASP categories, confidence.
- `errors`: Scanner execution errors and parse failures.

### 2.5 Installation & Packaging Requirements
- Available via PyPI: `pip install semgrep`.
- Standalone binary releases available for Linux (x86_64, arm64).
- Runtime dependencies: Python 3.8+ or native binary; minimal container footprint.

### 2.6 Limitations
- Open-source Semgrep Community engine performs intra-file taint tracking; inter-file taint tracking across complex class hierarchies requires Semgrep Pro (proprietary).
- High memory consumption on massive source files or deeply nested ASTs without bounds.

---

## 3. Scanner 2: Bandit

### 3.1 Purpose & Detection Capabilities
Bandit is a security-focused linter developed under PyCQA specifically for Python source code. It builds an AST from each Python module and evaluates AST nodes against known security plugins (e.g., weak cryptography, shell injection via subprocess, insecure file permissions, hardcoded SQL).

### 3.2 Cybersecurity Domains Supported
- **Web Application Security:** Detects SQL queries with formatted strings (`B608`), shell injection via `subprocess` or `os.system` (`B602`, `B605`), and unsafe deserialization (`B301: pickle`).
- **Network & Communication Security:** Detects disabled certificate validation in HTTP requests (`B501: requests_no_cert_validation`), insecure SSL versions (`B502`), and bad SSL defaults (`B503`).
- **Authentication & Access Control:** Detects weak cryptographic hashes like MD5/SHA1 (`B303`, `B324`) and pseudo-random generators (`B311: random`).
- **Dependency & Configuration Security:** Detects dangerous temp file creation (`B306: mktemp_q`) and world-writable file permissions (`B103: chmod`).

### 3.3 Input Requirements & Flags
- **Target Input:** Directory path or list of Python files.
- **Configuration Flags:**
  - `-r /workspace`: Recursive scanning of directory.
  - `-f json`: JSON output format to stdout.
  - `-q` / `--quiet`: Suppresses informational banner.
  - `-x <exclude_paths>`: Excludes tests, virtual environments, and caches.
  - `-c <config.yaml>`: Optional configuration specifying active/disabled test IDs.

### 3.4 Output Format & Parsing
Bandit outputs a single JSON structure:
- `results`: List of findings, each containing:
  - `test_id`: Rule ID (e.g., `B501`).
  - `test_name`: Name of the security check.
  - `issue_text`: Descriptive title/message.
  - `issue_severity`: `HIGH`, `MEDIUM`, or `LOW`.
  - `issue_confidence`: `HIGH`, `MEDIUM`, or `LOW`.
  - `filename`: Full or relative path to file.
  - `line_number`: Line where the AST node was identified.
  - `line_range`: Array of affected line numbers.
  - `code`: Multiline code snippet showing context.
- `metrics`: File counts and issue breakdown.
- `errors`: Files that could not be parsed due to Python syntax errors.

### 3.5 Installation & Packaging Requirements
- Available via PyPI: `pip install bandit`.
- Pure Python package; minimal dependencies (`pyyaml`, `rich`, `stevedore`).

### 3.6 Limitations
- Strictly limited to Python (`.py` files).
- Purely syntactic AST pattern analysis; lacks dataflow and taint tracking.
- Frequently flags benign calls in test code (e.g., `assert` statements or `random` used for non-security purposes).

---

## 4. Scanner 3: Gitleaks / detect-secrets

### 4.1 Purpose & Detection Capabilities
Gitleaks is a specialized secret detection engine that scans files and Git repositories for hardcoded credentials, API keys, private keys, authentication tokens, and passwords using regular expressions and Shannon entropy calculations.

### 4.2 Comparison & Tool Selection
- **Gitleaks (Primary Choice):** Fast Go-based binary, extensive default rule dictionary (over 160+ token formats including AWS, GCP, GitHub, Slack, Stripe, Private Keys), active rule updates, JSON/SARIF output, native directory scanning without requiring a git repository (`gitleaks dir /workspace --no-git`).
- **detect-secrets (Secondary / Baseline Alternative):** Python-based tool by Yelp; relies on a baseline JSON file. Useful for incremental scanning, but slower on large repositories and requires more manual configuration.
- **Selection Decision:** Thread Trace selects **Gitleaks** as the primary engine for secret scanning due to its speed, standalone binary packaging, zero external dependencies, and rich token dictionary.

### 4.3 Cybersecurity Domains Supported
- **Secrets & Sensitive Information Management (Exclusive Focus):** Dedicated entirely to detecting exposed secrets, keys, credentials, connection strings, and certificates.

### 4.4 Input Requirements & Flags
- **Target Input:** Directory path.
- **Configuration Flags:**
  - `dir /workspace`: Scans directory directly without requiring `.git` folder.
  - `--no-git`: Disables git log inspection; treats folder as static filesystem.
  - `--report-format json`: Formats findings into JSON.
  - `--report-path /tmp/gitleaks_output.json`: Writes output to file.
  - `--redact`: Redacts detected secret strings in findings to prevent credential propagation.
  - `--config <rules.toml>`: Optional custom rule configurations.

### 4.5 Output Format & Parsing
Gitleaks outputs a JSON array of objects:
- `RuleID`: Rule identifier (e.g., `aws-access-key-id`, `generic-api-key`).
- `Description`: Human-readable description.
- `File`: Path to file containing the match.
- `StartLine` / `EndLine`: Line range.
- `Secret`: Matched secret string (must be redacted immediately).
- `Match`: Surrounding code context line.
- `Entropy`: Calculated Shannon entropy score.

### 4.6 Installation & Packaging Requirements
- Precompiled static binary for Linux/amd64 and arm64.
- Can be installed into the scanner container via GitHub release download or Go package manager.

### 4.7 Limitations
- Cannot verify whether a discovered credential is valid or revoked (prohibited from making network probes).
- Produces false positives on high-entropy UUIDs, cryptographic hashes, random testing strings, and binary encoded data if exclusions are misconfigured.

---

## 5. Scanner 4: OSV-Scanner

### 5.1 Purpose & Detection Capabilities
OSV-Scanner is Google’s open-source vulnerability scanner that bridges application dependencies with the Open Source Vulnerabilities (OSV) database (https://osv.dev). It analyzes dependency manifests and lockfiles to identify known vulnerabilities (CVEs and GHSAs) affecting open-source packages.

### 5.2 Cybersecurity Domains Supported
- **Dependency & Configuration Security (Primary Focus):** Identifies published security advisories in Python (`requirements.txt`, `Pipfile.lock`, `poetry.lock`) and Node.js (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`).

### 5.3 Input Requirements & Flags
- **Target Input:** Path to source workspace or explicit lockfile paths.
- **Configuration Flags:**
  - `--json`: Outputs results in machine-readable JSON format.
  - `-r /workspace`: Recursively discovers supported lockfiles and manifests.
  - `--lockfile=<path>`: Directly scans a targeted manifest.
  - `--offline`: Optional mode utilizing a local cached vulnerability database snapshot when network isolation is enforced.

### 5.4 Output Format & Parsing
OSV-Scanner outputs a hierarchical JSON object:
- `results`: List of package scan packages, containing:
  - `source`: Manifest file path (e.g., `requirements.txt`).
  - `packages`: List of dependencies, including `name`, `version`, and `ecosystem`.
  - `vulnerabilities`: Array of OSV advisory objects, including:
    - `id`: Advisory ID (e.g., `GHSA-xxxx-yyyy-zzzz` or `CVE-2023-45803`).
    - `summary`: One-line summary of vulnerability.
    - `details`: Extended technical advisory details.
    - `severity`: CVSS v3 score / vector string.
    - `affected`: Version ranges vulnerable and fixed versions.

### 5.5 Installation & Packaging Requirements
- Single static Go binary distributed via GitHub releases (`osv-scanner`).
- Packaged inside the dedicated scanner container; zero runtime system dependencies.

### 5.6 Limitations
- Evaluates dependency version metadata only; does not perform AST reachability analysis (cannot determine if the vulnerable function inside the library is executed by first-party code).
- Manifests without explicit pinned versions (loose ranges in `requirements.txt`) may produce ambiguous advisory matches.

---

## 6. Scanner 5: Custom Security Rules

### 6.1 Purpose & Detection Capabilities
Custom security rules allow Thread Trace to enforce project-specific coding standards, company security policies, and specialized checks not covered by standard off-the-shelf scanner rulepacks.

### 6.2 Implementation Mechanisms
Custom rules are implemented in two modular forms:
1. **Semgrep Custom Rule Packs (`.yaml`):** Standard Semgrep YAML rule definitions matching syntactic AST patterns (e.g., enforcing that all FastAPI routes have explicit rate limits, or prohibiting direct calls to internal unauthenticated endpoints).
2. **Targeted Python AST / Regex Checks:** Lightweight Python scripts for specialized checks (e.g., checking custom configuration schemas or internal security headers).

### 6.3 Cybersecurity Domains Supported
- Can be created to cover any of the five domains where off-the-shelf rules have gaps (e.g., proprietary token formats under Secrets Management, or internal microservice communication under Network Security).

### 6.4 Limitations
- Custom rules require ongoing maintenance and documentation.
- Must be vetted against clean fixtures to avoid introducing high false-positive rates.

---

## 7. Overlapping Capabilities & Deduplication Strategy

Because multiple scanners evaluate the same workspace, overlapping detections will occur. Thread Trace resolves overlaps using a deterministic precedence hierarchy:

```
+-------------------------------------------------------------+
|                     Uploaded Workspace                      |
+-------------------------------------------------------------+
         |                       |                     |
         v                       v                     v
   [ Python Code ]        [ JS / TS Code ]      [ Manifests ]
         |                       |                     |
    Bandit + Semgrep          Semgrep             OSV-Scanner
         |                       |                     |
         +----------->  Deduplication  <---------------+
                             Engine
                               |
                               v
                     Normalized Findings
```

### 7.1 Semgrep vs. Bandit (Python Web & Code Flaws)
- **Overlap:** Both Semgrep and Bandit detect SQL injection, command injection, and insecure hash functions in Python.
- **Precedence Rule:** If both Semgrep and Bandit flag the same file and overlapping line range (+/- 2 lines) for the same underlying CWE (e.g., CWE-89 SQLi):
  - Retain the finding with the higher confidence rating.
  - If confidence is equal, retain Semgrep's finding due to richer taint context, and record Bandit's test ID in finding metadata.

### 7.2 Gitleaks vs. Semgrep (Secret Detections)
- **Overlap:** Semgrep has generic secret rules; Gitleaks has an exhaustive secret dictionary.
- **Precedence Rule:** Gitleaks takes primary precedence for all secret detections in Domain 1 (`Secrets & Sensitive Information Management`). Semgrep secret rules are disabled or filtered when Gitleaks is active to prevent duplicate alerts on the same token.

---

## 8. Summary Table of Selected Toolchain

| Scanner | Tool Version / Target | Execution Type | Target Domains | Output Format |
|---|---|---|---|---|
| **Semgrep** | Latest OSS release | CLI inside container | Web Security, Auth, Network, Config | JSON |
| **Bandit** | Latest PyPI release | CLI inside container | Web Security, Network, Auth, Config (Python) | JSON |
| **Gitleaks** | Latest stable binary | CLI inside container | Secrets & Sensitive Information Management | JSON |
| **OSV-Scanner** | Latest stable binary | CLI inside container | Dependency & Configuration Security | JSON |
| **Custom Rules** | Project YAML / AST | Ingested by Semgrep / Engine | All 5 Domains (targeted gaps) | Normalized JSON |
