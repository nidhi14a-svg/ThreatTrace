# Common Finding Compatibility Specification

**File:** `specs/COMMON_FINDING_COMPATIBILITY_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Collaborator:** Dev B — Backend Schema Owner  
**Implementation Targets:** `backend/app/schemas/finding.py`, `backend/app/scanners/normalizer.py`, `backend/tests/test_finding_compatibility.py`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 6, Task 6.2)  
**Status:** APPROVED & IMPLEMENTED  

---

## 1. Overview & Objectives

Thread Trace ingests static analysis findings from heterogeneous scanning tools:
- **Semgrep:** JSON AST match objects with `check_id`, `path`, `start/end` line/col dictionaries, and `extra` metadata.
- **Bandit:** Python security AST alerts with `test_id`, `issue_text`, `code`, `issue_severity`, and `issue_confidence`.
- **Gitleaks:** Secret detection reports with `RuleID`, `Description`, `StartLine`, `Secret`, and `Entropy`.
- **OSV-Scanner:** Open-source vulnerability advisories with `id`, `package`, `version`, `severity`, and `affected`.
- **Custom Rules Engine:** Python AST and pattern checks with structured rule metadata.

The purpose of this specification is to verify that **every scanner's output translates deterministically into Dev B's canonical `Finding` Pydantic model** (`backend/app/schemas/finding.py`), with complete schema safety and zero validation failures across all normal, edge, and malformed cases.

---

## 2. Canonical Finding Pydantic Schema

The canonical `Finding` model owned by Dev B is defined as:

```python
from typing import Literal
from pydantic import BaseModel, Field

class Finding(BaseModel):
    id: str
    domain: str
    rule_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    file: str
    line: int | None = None
    evidence: str
    confidence: str
    explanation: str | None = None
    recommendation: str | None = None
    tool: str
    raw_category: str | None = None
```

**Dev C Strict Boundary:** Dev C must not independently modify or redefine `backend/app/schemas/finding.py`. All scanner output must be formatted to comply with this exact model.

---

## 3. Field Compatibility & Normalization Rules

| Field | Type & Requirement | Scanner Translation & Invariants | Edge Case Handling |
|---|---|---|---|
| `id` | `str` (Required) | Prefixed with `find_` (e.g. `find_<uuid4_hex>`). | If missing in raw finding, generated dynamically via `find_{uuid.uuid4().hex[:12]}`. |
| `domain` | `str` (Required) | Canonical domain string (e.g. `"Web Application Security"`) or 10-domain identifier (`"injection"`). | Defaults to `"General Security"` if missing. |
| `rule_id` | `str` (Required) | Prefixed identifier: `semgrep.<id>`, `bandit.<id>`, `gitleaks.<id>`, `osv.<id>`, `custom.<id>`. | Defaults to `"rule_unknown"` if absent. |
| `title` | `str` (Required) | Concise human-readable title, bounded to at most 200 characters. | Defaults to `rule_id` if message/title is missing. |
| `severity` | `Literal["critical", "high", "medium", "low"]` | Normalizes uppercase/lowercase (`CRITICAL`, `High`, `WARNING`, `Error`, `Moderate`). | Any unknown/invalid severity safely maps to `"medium"`. |
| `file` | `str` (Required) | Relative POSIX path with forward slashes (`/`), without `./` or `../`. | Defaults to `"[UNKNOWN_FILE]"` if absent; backslashes replaced. |
| `line` | `int | None` (Optional) | 1-indexed line number for code findings. | Set to `None` for manifest findings (e.g. `requirements.txt`), lockfiles, or file-level alerts. String digits are safely cast to `int`. Non-numeric or `< 1` values become `None`. |
| `evidence` | `str` (Required) | Snippet or advisory text. Mandatory secret redaction applied. | Hard bounded to at most 1,000 characters. Null/empty values become `""`. |
| `confidence` | `str` (Required) | Normalized confidence string: `"high"`, `"medium"`, or `"low"`. | Unknown confidence strings safely default to `"medium"`. |
| `explanation` | `str | None` (Optional) | Initialized to scanner documentation or `None`. | Left as `None` for future asynchronous AI enrichment. |
| `recommendation` | `str | None` (Optional) | Initialized to scanner remediation advice or `None`. | Left as `None` for future asynchronous AI enrichment. |
| `tool` | `str` (Required) | Identifier of scanner engine: `"semgrep"`, `"bandit"`, `"gitleaks"`, `"osv-scanner"`, `"custom-rules"`. | Inferred from `ScannerExecutionResult.scanner_name` if missing in raw finding. |
| `raw_category` | `str | None` (Optional) | Native tool category (e.g. Bandit `test_name`, Semgrep `category`, Gitleaks `RuleID`). | Preserved if present; `None` otherwise. |

---

## 4. Verification Matrix

The test suite in `backend/tests/test_finding_compatibility.py` validates:

1. **Manifest-Level Findings (Null Line Numbers):** Dependency and whole-file findings instantiate with `line=None` without validation errors.
2. **Nullable AI Fields:** Findings with `explanation=None` and `recommendation=None` validate correctly.
3. **Unknown Categories:** Arbitrary tool categories or `raw_category=None` are safely handled.
4. **Invalid Severity & Domain Fallbacks:** Unsupported severity values (e.g. `"fatal"`, `"informational"`, `123`) fall back to `"medium"`.
5. **Evidence Truncation & Bounding:** Evidence strings longer than 1,000 characters are safely truncated to exactly 1,000 characters.
6. **Mandatory Redaction:** Evidence containing AWS keys, GitHub tokens, passwords, or private keys is redacted before instantiating the `Finding` model.
7. **Malformed Raw Findings:** Empty dictionaries, non-string values, and missing fields produce safe, schema-compliant `Finding` instances without crashing.
