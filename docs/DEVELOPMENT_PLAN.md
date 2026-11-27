# Development Plan

## Developer Responsibility Overview

- **Dev A — Frontend Developer:** Owns `frontend/` and the Next.js user experience.
- **Dev B — Backend Developer:** Owns FastAPI routes, services, schemas, models, database, orchestration, and AI integration under `backend/app/`.
- **Dev C — Cybersecurity, Scanner Integration & DevOps:** Owns scanner specifications and integrations, security rules, scanner containerization, security testing, and DevOps verification.

This document defines the planned implementation sequence without implementing the work described.

---

## Dev C — Cybersecurity, Scanner Integration & DevOps

### Phase 1 — Security Foundation & Specifications

**Objective:** Establish the security domain model, supported-source decisions, scanner-selection rationale, finding taxonomy, and secure execution requirements before scanner implementation begins.

**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps.

**Files:** `specs/`, `backend/app/scanners/`, `backend/app/schemas/finding.py`, `backend/app/core/security.py`, `.env.example`, `docs/SERVICE_INTERFACES_DEV_C.md`.

| Task | Specification | File/Directory | Specific implementation task |
|---|---|---|---|
| 1.1 | `specs/CYBERSECURITY_DOMAINS_SPEC.md` | `specs/CYBERSECURITY_DOMAINS_SPEC.md` | Define coverage and terminology for Secrets & Sensitive Information Management, Web Application Security, Network & Communication Security, Authentication & Access Control, and Dependency & Configuration Security. |
| 1.2 | `specs/SCANNER_LANGUAGE_SUPPORT_SPEC.md` | `specs/SCANNER_LANGUAGE_SUPPORT_SPEC.md` | Define initially supported source types and language/package ecosystems, including explicit exclusions and future-extension considerations. |
| 1.3 | `specs/SCANNER_SELECTION_SPEC.md` | `specs/SCANNER_SELECTION_SPEC.md` | Document the purpose and limitations of Semgrep, Bandit, Gitleaks/detect-secrets, OSV-Scanner, and custom rules; explain where each tool fits and avoid product-feature expansion. |
| 1.4 | `specs/FINDING_NORMALIZATION_SPEC.md` | `backend/app/schemas/finding.py` | Coordinate with Dev B to define scanner-neutral severity, confidence, domain, file, line, evidence, tool, rule, explanation, and recommendation mapping compatible with the common finding schema. |
| 1.5 | `specs/SEVERITY_CONFIDENCE_SPEC.md` | `specs/SEVERITY_CONFIDENCE_SPEC.md` | Define critical/high/medium/low severity rules and confidence classifications, including missing-line and unavailable-evidence behavior. |
| 1.6 | `specs/SECURE_SCAN_EXECUTION_SPEC.md` | `backend/app/core/security.py`, `.env.example` | Define resource limits, execution timeouts, network isolation, unprivileged execution, workspace boundaries, cleanup, retention, and secret-redaction requirements. |
| 1.7 | `specs/ZIP_ARCHIVE_SECURITY_SPEC.md` | `backend/app/services/extraction_service.py`, `backend/app/utils/file_utils.py` | Coordinate with Dev B on planned ZIP size limits, entry-count limits, compression-ratio limits, Zip Slip prevention, symlinks, duplicate names, and isolated extraction boundaries; Dev C owns the security requirements, while Dev B owns implementation. |
| 1.8 | `docs/SERVICE_INTERFACES_DEV_C.md` | `docs/SERVICE_INTERFACES_DEV_C.md` | Document the planned scanner-interface contract, normalized-result contract, orchestration inputs/outputs, and resource/time-limit settings agreed with Dev B. |

**Phase 1 Result:** Approved security specifications and interface boundaries are ready for scanner work, with no detection engine or scanner command implementation started.

---

### Phase 2 — Scanner Setup & Integration

**Objective:** Prepare modular scanner integrations that follow the shared `BaseScanner` interface and remain independent from orchestration and API implementation owned by Dev B.

**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps.

**Files:** `backend/app/scanners/`, `backend/app/scanners/base_scanner.py`, `backend/app/scanners/semgrep_scanner.py`, `backend/app/scanners/bandit_scanner.py`, `backend/app/scanners/secrets_scanner.py`, `backend/app/scanners/dependency_scanner.py`, `backend/app/ai/`, `specs/`.

| Task | Specification | File/Directory | Specific implementation task |
|---|---|---|---|
| 2.1 | `specs/SCANNER_INTERFACE_SPEC.md` | `backend/app/scanners/base_scanner.py` | Review and, if required by implementation agreement, extend the common `scan(workspace)` contract to include scanner identity, execution status, normalized findings, and bounded error reporting without moving orchestration into scanner classes. |
| 2.2 | `specs/SEMGREP_INTEGRATION_SPEC.md` | `backend/app/scanners/semgrep_scanner.py` | Define Semgrep invocation, supported targets, output parsing, timeout, workspace access, and web/application security rule mapping; coordinate command execution and container placement with the DevOps environment. |
| 2.3 | `specs/BANDIT_INTEGRATION_SPEC.md` | `backend/app/scanners/bandit_scanner.py` | Define Bandit invocation for Python files, JSON output parsing, severity/confidence conversion, evidence extraction, and mapping to the relevant security domains. |
| 2.4 | `specs/SECRET_SCANNER_INTEGRATION_SPEC.md` | `backend/app/scanners/secrets_scanner.py` | Define Gitleaks/detect-secrets selection or staged support, secret-scan scope, redaction requirements, rule/output parsing, and mapping to Secrets & Sensitive Information Management. |
| 2.5 | `specs/DEPENDENCY_SCANNER_INTEGRATION_SPEC.md` | `backend/app/scanners/dependency_scanner.py` | [COMPLETED] Define OSV-Scanner invocation and dependency-manifest coverage, normalized advisory conversion, severity handling, evidence preservation, and mapping to Dependency & Configuration Security. |
| 2.6 | `specs/SCANNER_OUTPUT_SPEC.md` | `backend/app/scanners/` | [COMPLETED] Establish parser and error boundaries for every scanner, ensuring raw evidence is retained safely and external AI processing never receives unsanitized repository content. |
| 2.7 | `specs/SCANNER_FAILURE_SPEC.md` | `backend/app/scanners/base_scanner.py`, `backend/app/scanners/` | [COMPLETED] Define partial success, timeout, missing binary, malformed output, and unsupported-language behavior so one scanner failure can be reported without corrupting other normalized findings. |
| 2.8 | `specs/AI_CONTEXT_BOUNDARY_SPEC.md` | `backend/app/ai/ai_service.py`, `backend/app/ai/prompts.py` | [COMPLETED] Coordinate with Dev B to define the sanitized finding-only context interface; scanner code must not send repositories or raw evidence to AI. AI output remains separate from verified evidence. |

**Phase 2 Result:** All planned scanner modules have documented integration boundaries and can produce normalized structures through independent implementations.

---

### Phase 3 — Custom Security Rules & Finding Normalization

**Objective:** Create maintainable custom detection coverage and produce consistent, traceable findings across all five domains.

**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps.

**Files:** `backend/app/scanners/custom_rules/`, `backend/app/scanners/`, `backend/app/schemas/finding.py`, `specs/`, `backend/tests/`.

| Task | Specification | File/Directory | Specific implementation task |
|---|---|---|---|
| 3.1 | `specs/CUSTOM_RULE_PACK_SPEC.md` | `backend/app/scanners/custom_rules/` | [COMPLETED] Define project-specific rule organization, rule identifiers, rule metadata, and maintainable loading conventions for future custom rules. |
| 3.2 | `specs/FIVE_DOMAIN_COVERAGE_SPEC.md` | `backend/app/scanners/custom_rules/`, `backend/app/scanners/` | [COMPLETED] Map tool and custom-rule coverage across all five cybersecurity domains, explicitly recording gaps rather than fabricating coverage. |
| 3.3 | `specs/SECRETS_MANAGEMENT_RULE_SPEC.md` | `backend/app/scanners/custom_rules/`, `backend/app/scanners/secrets_scanner.py` | [COMPLETED] Define detections for hardcoded credentials and sensitive values while ensuring evidence is redacted and preserve rule-level confidence. |
| 3.4 | `specs/WEB_SECURITY_RULE_SPEC.md` | `backend/app/scanners/custom_rules/`, `backend/app/scanners/semgrep_scanner.py` | [COMPLETED] Define custom web security coverage that complements, rather than duplicates, Semgrep and is limited to agreed supported patterns. |
| 3.5 | `specs/NETWORK_AUTH_RULE_SPEC.md` | `backend/app/scanners/custom_rules/` | [COMPLETED] Define narrowly scoped network/communication and authentication/access-control checks appropriate to static source analysis, including known limitations. |
| 3.6 | `specs/CONFIG_DEPENDENCY_RULE_SPEC.md` | `backend/app/scanners/custom_rules/`, `backend/app/scanners/dependency_scanner.py` | [COMPLETED] Define dependency, package, and configuration checks and align OSV advisories with Dependency & Configuration Security. |
| 3.7 | `specs/FINDING_NORMALIZATION_RULES.md` | `backend/app/scanners/`, `backend/app/schemas/finding.py` | [COMPLETED] Specify normalization of IDs, domains, rule IDs, titles, severity, file paths, optional line numbers, evidence, confidence, tool names, and nullable AI fields; coordinate schema updates with Dev B. |
| 3.8 | `specs/FALSE_POSITIVE_SPEC.md` | `backend/app/scanners/custom_rules/`, `backend/tests/` | [COMPLETED] Define deduplication, allowlisting, suppression boundaries, confidence adjustments, and false-positive review records; no automatic suppression that hides actionable evidence. |
| 3.9 | `specs/SECRET_REDACTION_SPEC.md` | `backend/app/scanners/`, `backend/app/core/security.py` | [COMPLETED] Define secret redaction patterns and invariant checks so secrets never enter logs, findings, reports, or AI context without prior approval. |

**Phase 3 Result:** Scanner findings are consistent, domain-mapped, redacted, severity-rated, confidence-rated, deduplicated, and traceable to their source tool.

---

### Phase 4 — Docker & DevOps

**Objective:** Provide a restricted, repeatable scanner environment and integrate required security tooling without exposing uploaded source code or credentials to unnecessary services.

**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps.

**Files:** `docker-compose.yml`, `backend/Dockerfile`, `backend/app/scanners/`, `specs/`, `scripts/`, `.env.example`, `Makefile`, `tests/`.

| Task | Specification | File/Directory | Specific implementation task |
|---|---|---|---|
| 4.1 | `specs/SCANNER_CONTAINER_ARCHITECTURE_SPEC.md` | `docker-compose.yml`, `specs/` | [COMPLETED] Plan a separate restricted scanner environment rather than running scanner binaries as privileged application containers. |
| 4.2 | `specs/SCANNER_DOCKERFILE_SPEC.md` | `backend/Dockerfile` or an approved dedicated scanner Dockerfile location | [COMPLETED] Specify minimal scanner images, pinned tool versions where available, non-root execution, read-only mounts where feasible, and no application service credentials. |
| 4.3 | `specs/COMPOSE_INTEGRATION_SPEC.md` | `docker-compose.yml` | [COMPLETED] Integrate scanner services or an execution path into existing frontend, backend, and MongoDB services while retaining service separation and avoiding unnecessary host ports. |
| 4.4 | `specs/CONTAINER_RESOURCE_LIMIT_SPEC.md` | `docker-compose.yml` | [COMPLETED] Define CPU, memory, process, timeout, disk, and scan-output limits; configure only values supported by the deployed Docker environment. |
| 4.5 | `specs/NETWORK_ISOLATION_SPEC.md` | `docker-compose.yml`, `backend/app/core/security.py` | [COMPLETED] Define restricted scanner networking, prevent outbound access unless explicitly required by an authenticated dependency tool, and prohibit source-code execution in application containers. |
| 4.6 | `specs/TEMP_WORKSPACE_SPEC.md` | `backend/app/services/extraction_service.py`, `backend/app/utils/file_utils.py`, `docker-compose.yml` | [COMPLETED] Define isolated temporary workspace paths, read-only source mounting, ownership, mount boundaries, retention duration, and cleanup behavior; Dev B implements extraction and orchestration. |
| 4.7 | `specs/CLEANUP_AND_RETENTION_SPEC.md` | `scripts/`, `backend/app/services/`, `docker-compose.yml` | [COMPLETED] Specify temporary archive, extracted workspace, container, log, and report cleanup procedures and retention boundaries. Dev B implements application cleanup hooks. |
| 4.8 | `specs/DEVOPS_COMMANDS_SPEC.md` | `Makefile`, `scripts/` | [COMPLETED] Add only commands needed to build, run, test, and clean the approved scanner environment; coordinate command names with existing Make targets before implementation. |
| 4.9 | `specs/SCANNER_SECRETS_CONFIG_SPEC.md` | `.env.example`, `.gitignore`, `docker-compose.yml` | [COMPLETED] Document secret-free configuration and environment-variable use for AI/provider credentials, database credentials, and optional scanner credentials. |

**Phase 4 Result:** The scanner environment is isolated, resource-bounded, repeatable, network-restricted, cleanable, and integrated without privileged containers or uploaded-code execution.

---

### Phase 5 — Security Testing & Validation

**Objective:** Validate scanner correctness, archive defenses, secret handling, failure behavior, and false-positive controls using controlled fixtures.

**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps.

**Files:** `backend/tests/`, `tests/`, `backend/app/scanners/`, `backend/app/services/`, `backend/app/utils/file_utils.py`, `specs/`, `scripts/`.

| Task | Specification | File/Directory | Specific implementation task |
|---|---|---|---|
| 5.1 | `specs/VULNERABLE_FIXTURE_SPEC.md` | `tests/fixtures/vulnerable/`, `backend/tests/fixtures/` | [COMPLETED] Prepare synthetic vulnerable sample projects for secrets, Python code patterns, web patterns, authentication/configuration issues, and dependency manifests; never use real credentials or production source. |
| 5.2 | `specs/CLEAN_FIXTURE_SPEC.md` | `tests/fixtures/clean/`, `backend/tests/fixtures/` | [COMPLETED] Prepare representative clean projects that exercise each scanner and support false-positive validation. |
| 5.3 | `specs/SCANNER_TEST_SPEC.md` | `backend/tests/` | [COMPLETED] Add scanner unit/integration test placeholders and expected normalized-result assertions for Semgrep, Bandit, Gitleaks/detect-secrets, OSV-Scanner, and custom rules. |
| 5.4 | `specs/ZIP_SECURITY_TEST_SPEC.md` | `backend/tests/test_upload.py`, `backend/tests/test_scans.py`, `tests/` | [COMPLETED] Coordinate test cases for oversized archives, excessive entries, compression ratio, Zip Slip, absolute paths, symlinks, duplicate names, and invalid ZIP files with Dev B's extraction implementation. |
| 5.5 | `specs/REDACTION_TEST_SPEC.md` | `backend/tests/`, `tests/` | [COMPLETED] Verify API keys, tokens, passwords, private keys, and scanner evidence are redacted from logs and reports while retaining useful finding location and rule context. |
| 5.6 | `specs/SCANNER_FAILURE_TEST_SPEC.md` | `backend/tests/`, `backend/app/scanners/` | [COMPLETED] Test unavailable binaries, malformed output, timeouts, resource termination, and partial scanner failure to ensure safe and diagnosable results. |
| 5.7 | `specs/FALSE_POSITIVE_VALIDATION_SPEC.md` | `backend/tests/`, `tests/` | [COMPLETED] Compare vulnerable fixtures against clean fixtures, record residual false positives, and validate allowlisting, deduplication, and confidence classifications. |
| 5.8 | `specs/CONTAINER_SECURITY_TEST_SPEC.md` | `tests/`, `docker-compose.yml` | [COMPLETED] Verify containers are unprivileged, scanner networking is restricted, source mounts are bounded, resource limits are enforced, and cleanup removes temporary data. |
| 5.9 | `specs/REPOSITORY_EXECUTION_TEST_SPEC.md` | `backend/tests/`, `tests/` | [COMPLETED] Verify that uploaded source code, build scripts, package setup hooks, and scanner fixtures are never executed by the application or general-purpose backend container. |

**Phase 5 Result:** The scanner set has reproducible positive and negative tests, archive abuse defenses are verified, and residual limitations are documented.

---

### Phase 6 — Backend Integration & Final Verification

**Objective:** Integrate the scanner modules into Dev B's orchestration boundary, verify the complete foundation, and prepare final security documentation.

**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps.

**Files:** `backend/app/services/scan_service.py`, `backend/app/scanners/`, `backend/app/schemas/`, `backend/tests/`, `tests/`, `docker-compose.yml`, `README.md`, `docs/SERVICE_INTERFACES_DEV_C.md`, `specs/`.

| Task | Specification | File/Directory | Specific implementation task |
|---|---|---|---|
| 6.1 | `specs/BACKEND_INTEGRATION_SPEC.md` | `backend/app/services/scan_service.py`, `backend/app/scanners/` | [COMPLETED] Depend on Dev B's approved orchestration interface and connect each scanner without duplicating scan-job, database, or API route logic owned by Dev B. |
| 6.2 | `specs/COMMON_FINDING_COMPATIBILITY_SPEC.md` | `backend/app/schemas/finding.py`, `backend/app/scanners/` | [COMPLETED] Verify every scanner adapter produces the exact Pydantic-compatible finding shape, including optional line numbers and nullable AI fields. |
| 6.3 | `specs/SCANNER_REPORT_MAPPING_SPEC.md` | `backend/app/services/scan_service.py`, `backend/app/services/report_service.py` | [COMPLETED] Agree with Dev B on normalized finding aggregation and domain/status summaries; scanner modules must not own report formatting or API response conventions. |
| 6.4 | `specs/END_TO_END_SECURITY_TEST_SPEC.md` | `backend/tests/`, `tests/` | [COMPLETED] Run controlled end-to-end tests from ZIP upload through isolated extraction, scanner execution, normalization, reporting, and deletion; Dev B owns workflow implementation. |
| 6.5 | `specs/DELETE_RETENTION_TEST_SPEC.md` | `backend/tests/`, `tests/` | [COMPLETED] Coordinate verification that delete operations remove temporary workspaces, scan data, and scanner artifacts within the documented retention boundary. |
| 6.6 | `specs/SECURITY_VERIFICATION_SPEC.md` | `docs/`, `specs/`, `docker-compose.yml` | [COMPLETED] Perform final verification of Zip Slip, ZIP bomb limits, secret redaction, unprivileged execution, network isolation, resource limits, cleanup, and sensitive configuration handling. |
| 6.7 | `specs/SCANNER_LIMITATIONS_SPEC.md` | `docs/SERVICE_INTERFACES_DEV_C.md`, `README.md` | [COMPLETED] Document scanner coverage, unsupported languages, static-analysis limitations, false-positive expectations, and conditions requiring follow-up assessment. |
| 6.8 | `specs/FINAL_SECURITY_OPERATIONS_SPEC.md` | `README.md`, `Makefile`, `docker-compose.yml` | [COMPLETED] Document startup, scanner dependency, test, resource, cleanup, and troubleshooting operations for the team without exposing credentials. |
| 6.9 | `docs/SERVICE_INTERFACES_DEV_C.md` | `docs/SERVICE_INTERFACES_DEV_C.md` | [COMPLETED] Finalize scanner contracts, normalized finding mapping, execution limits, failure semantics, and Dev B integration responsibilities. |

**Phase 6 Result:** Dev C's scanner and DevOps modules integrate cleanly with Dev B's backend and satisfy the documented security verification requirements.

---

## Dev C Final Deliverables

1. Security specifications for domains, scanner selection, severity/confidence mapping, archive safety, secret redaction, and secure execution.
2. Modular adapters for Semgrep, Bandit, Gitleaks/detect-secrets, OSV-Scanner, and custom rules behind the common scanner interface.
3. Scanner output normalization compatible with the shared finding schema.
4. Five-domain scanner coverage mapping with explicitly documented limitations.
5. Restricted scanner containers or an approved equivalent isolated execution environment.
6. Docker Compose integration, resource limits, temporary workspace controls, cleanup, and retention procedures.
7. Synthetic vulnerable and clean test fixtures.
8. Security and integration test coverage for ZIP validation, redaction, false positives, scanner failures, container isolation, and backend orchestration.
9. Final scanner interface and operational documentation.

### Expected Completed Modules

- `backend/app/scanners/base_scanner.py`
- `backend/app/scanners/semgrep_scanner.py`
- `backend/app/scanners/bandit_scanner.py`
- `backend/app/scanners/secrets_scanner.py`
- `backend/app/scanners/dependency_scanner.py`
- `backend/app/scanners/custom_rules/`
- Scanner-related portions of `backend/tests/`
- Docker and DevOps configuration in `docker-compose.yml` and the approved dedicated scanner Docker configuration
- Security specifications under `specs/`
- Finalized scanner documentation under `docs/SERVICE_INTERFACES_DEV_C.md`

### Testing Requirements

- Static and integration tests must cover each supported scanner adapter and malformed scanner output.
- Finding normalization tests must cover all supported severities, all five domains, optional line numbers, and redacted evidence.
- ZIP security tests must cover Zip Slip, oversize archives, excessive entries, compression ratio, symlinks, duplicate names, and invalid files.
- Vulnerable and clean fixtures must verify detection coverage and false-positive behavior without real credentials or vulnerable third-party services.
- Container tests must verify unprivileged execution, bounded resources, restricted networking, read-only or isolated source access, and cleanup.
- Backend integration tests must verify compatibility with Dev B's scan orchestration and report services.

### Definition of Done

Dev C's responsibilities are complete only when all five domains have documented and tested mapping; each approved scanner has a modular, non-privileged integration boundary; findings conform to the common schema; evidence is redacted and AI receives sanitized context only; uploaded ZIPs are not executed and extraction boundaries are documented; scanner containers use resource limits and isolated workspaces; temporary data and reports follow cleanup/retention behavior; scanner failures are handled safely; false-positive limitations are recorded; vulnerable and clean fixtures pass in CI or team test runs; Docker Compose starts the required application services; and Dev C's final interfaces and operations are documented for Dev B and Dev A.
