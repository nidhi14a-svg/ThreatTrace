# Finding Normalization Rules Specification

**File:** `specs/FINDING_NORMALIZATION_RULES.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Targets:** `backend/app/scanners/normalizer.py`, `backend/app/schemas/finding.py`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 3, Task 3.7)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

Thread Trace integrates five heterogeneous vulnerability scanners (Semgrep, Bandit, Gitleaks, OSV-Scanner, and Custom Rules). Each engine emits findings in its own native format, with distinct severity naming, classification taxonomies, confidence metrics, and coordinate systems.

This specification establishes the **Finding Normalization Engine** that transforms raw scanner finding dictionaries (`ScannerExecutionResult.findings`) into instances of the canonical `Finding` schema (`backend/app/schemas/finding.py`).

### 1.1 Invariants of Normalization
1. **Provenance Preservation:** The scanner identity (`tool`) and rule identifier (`rule_id`) are preserved.
2. **Original Classification Retention:** Tool-native categorization is preserved in the optional `raw_category` field.
3. **Coordinate Normalization:** All file paths are normalized to workspace-relative POSIX paths (`/`). Line numbers are 1-indexed integers or `None` (for file- or manifest-level findings).
4. **Mandatory Redaction & Bounding:** Evidence strings must never contain unmasked credentials and are capped at 1,000 characters.
5. **AI Segregation:** `explanation` and `recommendation` fields are initialized to `None` or scanner rule descriptions, awaiting asynchronous AI enrichment.

---

## 2. Canonical Finding Schema Alignment

The shared `Finding` model (`backend/app/schemas/finding.py`) defines the normalized shape:

```python
class Finding(BaseModel):
    id: str                                                  # Unique finding ID (e.g. 'find_a1b2c3d4e5f6')
    domain: str                                              # Canonical domain or display domain
    rule_id: str                                             # Prefixed rule ID (e.g. 'bandit.B608')
    title: str                                               # Vulnerability title (max 200 chars)
    severity: Literal["critical", "high", "medium", "low"]  # Normalized severity tier
    file: str                                                # Relative POSIX path
    line: int | None = None                                  # Line number (None for manifest/file-level)
    evidence: str                                            # Redacted snippet (max 1,000 chars)
    confidence: str                                          # Normalized: "high", "medium", "low"
    explanation: str | None = None                           # Enriched by AI service
    recommendation: str | None = None                        # Enriched by AI service
    tool: str                                                # Scanner engine: semgrep, bandit, gitleaks, osv-scanner, custom-rules
    raw_category: str | None = None                          # Original tool category
```

---

## 3. Tool-by-Tool Normalization Mapping

| Field | Semgrep Raw Mapping | Bandit Raw Mapping | Gitleaks Raw Mapping | OSV-Scanner Raw Mapping | Custom Rules Raw Mapping |
|---|---|---|---|---|---|
| `id` | `uuid4` prefix `find_` | `uuid4` prefix `find_` | `uuid4` prefix `find_` | `uuid4` prefix `find_` | `uuid4` prefix `find_` |
| `domain` | Mapped via rule tags (`injection`, `auth`) | Mapped via test ID range (`injection`, `crypto`) | `"secrets"` (or `"Secrets Management"`) | `"dependencies"` | `rule.domain` / `canonical_domain` |
| `rule_id` | `semgrep.<check_id>` | `bandit.<test_id>` | `gitleaks.<RuleID>` | `osv.<vuln_id>` | `<rule.rule_id>` |
| `title` | `extra.message` (first sentence) | `issue_text` | `Description` | `summary` or `details` (first line) | `rule.title` |
| `severity` | `ERROR` -> `high`/`critical`<br>`WARNING` -> `medium`<br>`INFO` -> `low` | `HIGH` -> `high`<br>`MEDIUM` -> `medium`<br>`LOW` -> `low` | Cloud/Key -> `critical`<br>SaaS -> `high`<br>Generic -> `medium` | CVSS >=9 -> `critical`<br>7-8.9 -> `high`<br>4-6.9 -> `medium`<br><4 -> `low` | `rule.severity` |
| `file` | Relative `path` | Relative `filename` | Relative `File` | Relative `source.path` | Relative `file` |
| `line` | `start.line` | `line_number` | `StartLine` | `None` | `line` |
| `evidence` | `extra.lines` (redacted, <=1000) | `code` (redacted, <=1000) | `Match` (redacted, <=1000) | Synthesized statement (<=1000) | Evaluated snippet (redacted, <=1000) |
| `confidence` | `extra.metadata.confidence` | `issue_confidence` | `"high"` | Lockfile -> `high`<br>Manifest -> `medium` | `rule.confidence` |
| `tool` | `"semgrep"` | `"bandit"` | `"gitleaks"` | `"osv-scanner"` | `"custom-rules"` |
| `raw_category` | `extra.metadata.category` | `test_name` | `RuleID` | `"dependency_vulnerability"` | `rule.raw_category` |

---

## 4. Normalizer Engine Implementation (`normalizer.py`)

A pure functional normalizer transforms raw dictionaries into `Finding` instances:
- Guarantees valid field types and defaults.
- Verifies that `evidence` contains no unmasked credentials.
- Bounds string fields.
- Normalizes paths using forward slashes (`/`).
