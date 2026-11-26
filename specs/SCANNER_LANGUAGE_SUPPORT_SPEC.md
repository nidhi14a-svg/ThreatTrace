# Scanner Language Support Specification

- **Document:** `specs/SCANNER_LANGUAGE_SUPPORT_SPEC.md`
- **Project:** Thread Trace — Source-Code Vulnerability Detection Platform
- **Owner:** Dev C (Cybersecurity, Scanner Integration & DevOps)
- **Status:** Approved Specification (Phase 1)
- **Version:** 1.0.0

---

## 1. Executive Summary & Scope

Thread Trace provides focused, high-fidelity static analysis for uploaded source repositories. To prevent scope creep, excessive scanner execution times, and resource exhaustion, Phase 1 defines strict boundaries for supported programming languages, file extensions, and dependency ecosystems.

The primary target languages for initial release are **Python** and **JavaScript / TypeScript**, reflecting the dominant modern full-stack web application development stacks and the direct composition of Thread Trace itself.

---

## 2. Initially Supported Programming Languages

| Language / Platform | Target Version Support | Primary Scanner Coverage | Rationale |
|---|---|---|---|
| **Python** | Python 3.8 – 3.12+ | Bandit, Semgrep, OSV-Scanner, Gitleaks, Custom Rules | Universal backend and data language; comprehensive AST security rules via Bandit and Semgrep. |
| **JavaScript / TypeScript** | ECMAScript 2018+, TypeScript 4.0 – 5.x | Semgrep, OSV-Scanner, Gitleaks, Custom Rules | Dominant frontend and Node.js backend ecosystem; extensive Semgrep rule registry coverage for web vulnerabilities. |
| **Configuration & Manifests** | YAML 1.2, JSON, TOML, .env | Semgrep, OSV-Scanner, Gitleaks, Custom Rules | Essential for detecting security misconfigurations, cleartext credentials, and vulnerable package dependencies. |

---

## 3. Supported Source-Code File Types and Extensions

Scanners must only evaluate source files matching the explicit whitelist below. Files with unrecognized or unsupported extensions must be skipped to avoid unnecessary processing and false positives.

| File Type Category | Extensions / File Patterns | Processing Scanner(s) | Description |
|---|---|---|---|
| **Python Source** | `.py` | Bandit, Semgrep, Gitleaks, Custom Rules | Python application modules, scripts, test files, and utilities. |
| **JavaScript Source** | `.js`, `.mjs`, `.cjs` | Semgrep, Gitleaks, Custom Rules | ECMAScript modules, CommonJS scripts, Node.js controllers. |
| **React / JSX Source** | `.jsx` | Semgrep, Gitleaks, Custom Rules | Client-side React components with JSX template syntax. |
| **TypeScript Source** | `.ts`, `.mts`, `.cts` | Semgrep, Gitleaks, Custom Rules | Typed TypeScript application code and interfaces. |
| **TypeScript JSX Source**| `.tsx` | Semgrep, Gitleaks, Custom Rules | React TypeScript components and Next.js page routes. |
| **JSON Configuration** | `.json` (excluding lockfiles) | Semgrep, Gitleaks, Custom Rules | Application settings, tsconfig.json, policy documents. |
| **YAML Configuration** | `.yaml`, `.yml` | Semgrep, Gitleaks, Custom Rules | Application configurations, CI/CD pipelines, Docker Compose files. |
| **Environment Files** | `.env`, `.env.example`, `.env.local` | Gitleaks, Semgrep, Custom Rules | Environment variable templates and local configuration files. |
| **TOML Configuration** | `.toml` (e.g., `pyproject.toml`) | OSV-Scanner, Semgrep, Gitleaks | Modern Python package metadata and tool configurations. |

---

## 4. Supported Dependency Manifests and Package Ecosystems

Dependency and Software Composition Analysis (SCA) is driven by **OSV-Scanner**, targeting deterministic package manifests and lockfiles.

| Ecosystem | Manifest / Lockfile Name | Lockfile Present? | Detection Capabilities |
|---|---|---|---|
| **Python (pip)** | `requirements.txt` | Optional | Resolves exact versions if pinned (`pkg==1.2.3`). Loose ranges (`pkg>=1.0`) provide best-effort advisory matching. |
| **Python (Pipenv)** | `Pipfile.lock` | Required | Full deterministic resolution of direct and transitive dependencies with package hashes. |
| **Python (Poetry)** | `poetry.lock` | Required | Full deterministic resolution of dependency graph for OSV-Scanner. |
| **Python (PyPA)** | `pyproject.toml` | Optional | Resolves project dependencies declared under PEP 621 or Poetry metadata sections. |
| **Node.js (npm)** | `package-lock.json` | Required (Preferred) | Full dependency tree, including exact resolved versions and transitive package graphs. |
| **Node.js (npm)** | `package.json` | Optional (Fallback) | Best-effort resolution of top-level dependencies; may lack precise lockfile versions if ranges (`^`, `~`) are used. |
| **Node.js (Yarn)** | `yarn.lock` | Required | Deterministic lockfile resolution for Yarn-managed projects. |
| **Node.js (pnpm)** | `pnpm-lock.yaml` | Required | Deterministic lockfile resolution for pnpm-managed projects. |

---

## 5. Scanner Compatibility Matrix

The table below delineates exact tool applicability across each file category:

| File / Target Pattern | Semgrep | Bandit | Gitleaks / detect-secrets | OSV-Scanner | Custom Security Rules |
|---|:---:|:---:|:---:|:---:|:---:|
| Python Source (`.py`) | YES | YES | YES | NO | YES |
| JavaScript (`.js`, `.mjs`, `.cjs`) | YES | NO | YES | NO | YES |
| TypeScript (`.ts`, `.mts`, `.cts`) | YES | NO | YES | NO | YES |
| React Components (`.jsx`, `.tsx`)| YES | NO | YES | NO | YES |
| JSON (`.json`) | YES | NO | YES | NO | YES |
| YAML (`.yaml`, `.yml`) | YES | NO | YES | NO | YES |
| Python Manifests (`requirements.txt`, etc.) | NO | NO | YES | YES | YES |
| npm Manifests (`package.json`, `package-lock.json`) | NO | NO | YES | YES | YES |
| Generic Text / Readme (`.txt`, `.md`) | NO | NO | YES | NO | NO |

*Note: Bandit is strictly limited to Python ASTs and must not be invoked on non-Python files.*

---

## 6. Explicit Exclusions

To ensure security, operational stability, and rapid turnaround, the following file types, directories, and artifacts are strictly excluded from scanner execution:

### 6.1 Binary & Compiled Code
- **Executables and Libraries:** `.exe`, `.dll`, `.so`, `.dylib`, `.bin`, `.hex`, `.iso`.
- **Bytecode and Compiled Objects:** `.pyc`, `.pyo`, `.pyd`, `.class`, `.jar`, `.war`, `.ear`.
- **Native Object Files:** `.o`, `.a`, `.lib`, `.obj`.

### 6.2 Recursive / Nested Archives
- **Archives within Archives:** `.zip`, `.tar`, `.gz`, `.tgz`, `.bz2`, `.xz`, `.7z`, `.rar`.
- *Security Requirement:* Thread Trace does not recursively extract archives discovered within the uploaded project directory to prevent decompression loops and nested zip-bomb attacks.

### 6.3 Media & Static Assets
- **Images:** `.png`, `.jpg`, `.jpeg`, `.gif`, `.ico`, `.svg`, `.webp`, `.bmp`, `.tiff`.
- **Audio / Video:** `.mp4`, `.mp3`, `.wav`, `.mov`, `.avi`, `.webm`.
- **Documents & Fonts:** `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.woff`, `.woff2`, `.eot`, `.ttf`, `.otf`.

### 6.4 Third-Party Dependencies and Build Output Directories
Scanner jobs must exclude pre-existing dependency directories within uploaded projects to avoid scanning external third-party code as first-party code (dependency vulnerabilities are scanned exclusively via manifests):
- `node_modules/`
- `.venv/`, `venv/`, `env/`, `__pypackages__/`
- `.git/`, `.svn/`, `.hg/`
- `.next/`, `dist/`, `build/`, `out/`
- `__pycache__/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`
- `coverage/`, `.nyc_output/`

### 6.5 Minified Production Bundles
- Files matching `*.min.js`, `*.min.css`, `*-bundle.js`, `*.chunk.js`.
- *Reasoning:* Minified code strips AST syntactic structure, causing excessive false positives and slow AST traversal without providing actionable source line locations.

---

## 7. Future Extension Possibilities (Roadmap)

Future phases beyond initial release may consider adding support for additional ecosystems following justified demand and architectural review:

1. **Go Language (`.go`, `go.mod`, `go.sum`):**
   - High priority for cloud-native infrastructure code. Supported well by Semgrep and Google's `govulncheck`.
2. **Infrastructure as Code (IaC):**
   - Terraform (`.tf`), Dockerfile, Kubernetes manifests (`.yaml`).
   - Can be covered via Semgrep IaC rule packs or integrating specialized tools (Trivy, Checkov).
3. **Java / Kotlin (`.java`, `.kt`, `pom.xml`, `build.gradle`):**
   - Enterprise enterprise backend support. Semgrep provides extensive Java rules; OSV-Scanner supports Maven and Gradle locks.
4. **Rust (`.rs`, `Cargo.toml`, `Cargo.lock`):**
   - Systems programming language; supported by OSV-Scanner (`Cargo.lock`) and Semgrep.

*Decision Rule:* No extension to additional languages will be implemented during Phase 1 or Phase 2 without formal coordination with Dev B and Dev A.
