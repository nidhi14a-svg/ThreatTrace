# Custom Rule Pack Architecture Specification

**File:** `specs/CUSTOM_RULE_PACK_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Target:** `backend/app/scanners/custom_rules/`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 3, Task 3.1)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

This specification establishes the modular **Custom Security Rule Engine** for Thread Trace. While off-the-shelf scanners (Semgrep, Bandit, Gitleaks, OSV-Scanner) provide baseline static analysis, custom rules allow Thread Trace to enforce project-specific coding guidelines, catch framework-specific antipatterns, and provide coverage across specialized security scenarios.

### 1.1 Core Design Goals
1. **Modularity & Scalability:** Rules are organized into discrete domain packages under `backend/app/scanners/custom_rules/` rather than a monolithic script.
2. **Standardized Identity & Metadata:** Every custom rule possesses a unique prefixed identifier (`custom.<domain>.<rule-slug>`), canonical severity, detection confidence, CWE mappings, and file targeting constraints.
3. **Fault-Isolated Execution:** An error, malformed regex, or unhandled exception in one rule must never crash other rules, the custom scanner adapter, or the backend orchestrator.
4. **Integration with `BaseScanner` Contract:** The custom rule framework is wrapped in `CustomRulesScanner` (inheriting from `BaseScanner`), producing standardized raw findings conforming to `ScannerExecutionResult.findings`.
5. **Safe Evidence Context:** Evidence extracted by custom rules is strictly bounded (maximum 1,000 characters) and automatically passed through mandatory in-memory credential redaction.

---

## 2. Directory & Package Structure

```
backend/app/scanners/custom_rules/
│
├── __init__.py                # Package exports (CustomRulesScanner, RuleRegistry, BaseCustomRule)
├── base_rule.py               # Abstract base class: BaseCustomRule
├── registry.py                # Rule registry, discovery, loading, and validation
├── scanner.py                 # CustomRulesScanner adapter (inheriting BaseScanner)
│
├── secrets/                   # Secrets & Sensitive Information Rules (Task 3.3)
│   ├── __init__.py
│   ├── hardcoded_credentials.py
│   └── connection_strings.py
│
├── web/                       # Web Application Security Rules (Task 3.4)
│   ├── __init__.py
│   ├── sql_injection.py
│   ├── command_injection.py
│   ├── path_traversal.py
│   └── insecure_deserialization.py
│
├── auth/                      # Authentication & Access Control Rules (Task 3.5)
│   ├── __init__.py
│   ├── weak_password_hashing.py
│   └── hardcoded_jwt_secret.py
│
├── network/                   # Network & Communication Security Rules (Task 3.5)
│   ├── __init__.py
│   ├── disabled_tls.py
│   └── cleartext_http.py
│
└── config/                    # Configuration & Dependency Security Rules (Task 3.6)
    ├── __init__.py
    ├── debug_mode.py
    ├── insecure_cors.py
    └── unpinned_dependencies.py
```

---

## 3. Rule Identifier & Naming Conventions

All custom rules must adhere to the standardized hierarchical format:

`custom.<domain_category>.<specific_issue_slug>`

### Examples:
- `custom.secrets.hardcoded-api-key`
- `custom.secrets.database-connection-string`
- `custom.web.sql-injection-fstring`
- `custom.web.path-traversal-open`
- `custom.web.insecure-pickle-loads`
- `custom.network.disabled-tls-verify`
- `custom.network.cleartext-http-endpoint`
- `custom.auth.weak-md5-hashing`
- `custom.auth.hardcoded-jwt-secret`
- `custom.config.debug-mode-enabled`
- `custom.config.wildcard-cors-allow-credentials`

---

## 4. `BaseCustomRule` Class Specification

Every rule must inherit from `BaseCustomRule` defined in `base_rule.py`:

```python
class BaseCustomRule(ABC):
    """Abstract base class for all Thread Trace custom security detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier (e.g. 'custom.web.sql-injection-fstring')."""
        raise NotImplementedError

    @property
    @abstractmethod
    def title(self) -> str:
        """Concise, human-readable vulnerability title."""
        raise NotImplementedError

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed technical summary of the security risk."""
        raise NotImplementedError

    @property
    @abstractmethod
    def domain(self) -> str:
        """Canonical project-level domain (e.g. 'Web Application Security')."""
        raise NotImplementedError

    @property
    @abstractmethod
    def canonical_domain(self) -> str:
        """Strict backend domain slug (e.g. 'injection', 'secrets', 'authentication')."""
        raise NotImplementedError

    @property
    @abstractmethod
    def severity(self) -> Literal["critical", "high", "medium", "low"]:
        """Normalized severity tier."""
        raise NotImplementedError

    @property
    @abstractmethod
    def confidence(self) -> Literal["high", "medium", "low"]:
        """Detection confidence tier."""
        raise NotImplementedError

    @property
    @abstractmethod
    def file_extensions(self) -> tuple[str, ...]:
        """Tuple of supported lowercase file extensions (e.g. ('.py', '.js', '.ts'))."""
        raise NotImplementedError

    @property
    def cwe_id(self) -> int | None:
        """Optional Common Weakness Enumeration ID."""
        return None

    @abstractmethod
    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        """
        Evaluate file content for security vulnerabilities.

        Args:
            file_path: Relative POSIX path to the target file.
            content: Entire text content of the file.
            lines: List of lines in the file.

        Returns:
            list[dict[str, Any]]: List of raw finding dictionaries.
        """
        raise NotImplementedError
```

---

## 5. Rule Discovery, Registry & Validation (`registry.py`)

The `RuleRegistry` manages rule registration, validation, and invocation:

1. **Validation Checks on Registration:**
   - `rule_id` starts with `custom.` and contains at least two segments.
   - `severity` is one of `critical`, `high`, `medium`, `low`.
   - `confidence` is one of `high`, `medium`, `low`.
   - `file_extensions` is a non-empty tuple of lowercase extensions starting with `.`.
   - `canonical_domain` matches one of the 10 backend domains.
2. **Safe Execution Confinement:**
   - Invoking a rule is wrapped in a `try...except Exception` block.
   - If a rule raises an unhandled exception, the registry logs a warning, skips the faulty rule for that file, and continues executing remaining rules.
3. **File Filter Optimizations:**
   - Files matching ignored patterns (`.git/`, `node_modules/`, `__pycache__/`, `dist/`, `build/`) are skipped before invoking rules.
   - Only rules whose `file_extensions` match the file extension are evaluated.

---

## 6. Integration with `BaseScanner` (`CustomRulesScanner`)

The `CustomRulesScanner` adapter in `scanner.py` bridges the custom rule engine with the platform:
- Inherits from `BaseScanner`.
- `name: str = "custom-rules"`.
- Asynchronous `scan(workspace: str) -> ScannerExecutionResult`:
  1. Validates workspace directory and skips cleanly if workspace is empty or does not exist.
  2. Traverses files matching registered rule extensions.
  3. Evaluates all applicable rules per file.
  4. Bounds evidence to 1,000 characters and applies in-memory secret redaction.
  5. Returns `ScannerExecutionResult(scanner_name="custom-rules", status="success", findings=all_findings)`.

---

## 7. Developer & Team Boundaries

- **Dev C Owns:** The rule engine, rule pack directory structure, rule metadata validation, and all custom rule implementations.
- **Dev B Owns:** Ingesting `ScannerExecutionResult` with `scanner_name="custom-rules"` and normalizing its raw finding dictionaries into the MongoDB database.
- **Dev A Owns:** Displaying findings tagged with `tool="custom-rules"`.
