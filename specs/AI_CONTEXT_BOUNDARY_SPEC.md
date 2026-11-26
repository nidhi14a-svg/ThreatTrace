# AI Context Boundary Specification: Finding-Only Sanitized Context

**File:** `specs/AI_CONTEXT_BOUNDARY_SPEC.md`  
**Developer:** Dev C — Cybersecurity, Scanner Integration & DevOps  
**Implementation Targets:** `backend/app/ai/ai_service.py`, `backend/app/ai/prompts.py`, `backend/app/ai/__init__.py`  
**Reference Document:** `docs/DEVELOPMENT_PLAN.md` (Phase 2, Task 2.8)  
**Status:** COMPLETE  

---

## 1. Overview & Objectives

This specification defines the **AI Context Boundary & Sanitization Interface** between Dev C's cybersecurity scanner architecture and Dev B's AI explanation service in Thread Trace.

Thread Trace leverages Large Language Models (LLMs) (such as Google Gemini, Anthropic Claude, or OpenAI GPT) to enrich security findings with developer-friendly vulnerability explanations and actionable remediation steps. However, transmitting proprietary source code, full repositories, or raw credentials to third-party AI APIs introduces severe data leakage, compliance, and IP risks.

### Core Security Mandates
1. **Zero Repository Transmissions:** The scanner code and AI integration must **never** send entire repositories, full source code files, directory structures, or process memory dumps to an external AI service.
2. **Finding-Only Context:** Downstream AI prompts must receive **strictly** the pre-sanitized finding metadata (`rule_id`, `domain`, `title`, `severity`, `file`, `line`, bounded `evidence`, `confidence`).
3. **Mandatory Redaction Gate:** Evidence containing detected secrets must be redacted before constructing the AI prompt context.
4. **Additive-Only AI Constraint:** AI generation is strictly additive. LLM responses populate `finding.explanation` and `finding.recommendation`, and must **never** overwrite or alter the scanner's verified `evidence`, `severity`, `rule_id`, or `file` location.
5. **Architectural Separation:** Scanner modules (`backend/app/scanners/`) must not call AI APIs. Dev B's `ai_service.py` owns AI provider invocation during post-scan report enrichment.

---

## 2. Forbidden vs. Permitted AI Context Payloads

```
+-----------------------------------------------------------------------------------+
|                        Uploaded Repository / Workspace                            |
+-----------------------------------------------------------------------------------+
                                         |
                                         x   <-- [STRICT HARD BLOCK: Never to AI]
                                         |
                                         v
                         [ Scanner Adapters & Rules ]
                       (Semgrep, Bandit, Gitleaks, OSV)
                                         |
                                         v
                       [ Verified Finding Dictionaries ]
                                         |
                                         v
                       +----------------------------------+
                       |   AI Context Sanitization Gate   |
                       | - Filters allowed fields only    |
                       | - Validates bounded evidence     |
                       | - Asserts credential redaction   |
                       +----------------------------------+
                                         |
                                         v
                             [ AIFindingContext Model ]
                                         |
                                         v
                          [ Dev B AI Service Client ]
                              (Gemini / OpenAI)
                                         |
                                         v
                             [ AIEnrichmentResult ]
                         - explanation (Additive)
                         - recommendation (Additive)
```

### 2.1 Forbidden AI Payloads (Strictly Prohibited)
- Entire repository archives or extracted workspace folders.
- Complete unflagged source code files or modules.
- Surrounding file context exceeding 1,000 characters.
- System environment variables or configuration files containing credentials (`.env`).
- Raw, unmasked secret strings (API keys, private keys, database passwords).
- Host system paths outside the normalized relative workspace coordinates.

### 2.2 Permitted AI Context Payloads
Only the following structured metadata fields may be provided to the AI service:
- `finding_id`: Stable identifier of the finding.
- `rule_id`: Identifier of the rule or advisory (e.g., `bandit.B608`, `GHSA-...`).
- `domain`: Canonical cybersecurity domain title (e.g., `"Web Application Security"`).
- `title`: Short human-readable title of the vulnerability.
- `severity`: Normalized tier (`critical`, `high`, `medium`, `low`).
- `file`: Relative workspace path (e.g., `app/routes/auth.py`).
- `line`: 1-indexed positive integer or `None` (for manifest-level findings).
- `evidence`: Redacted code snippet or synthetic description (maximum 1,000 characters).
- `confidence`: Normalized confidence tier (`high`, `medium`, `low`).

---

## 3. The `AIFindingContext` Data Contract

The data contract between scanner output and the AI service is formalized via the `AIFindingContext` Pydantic model:

```python
class AIFindingContext(BaseModel):
    """
    Sanitized, bounded finding context passed to Dev B's AI service.
    Guarantees that no repository files, unredacted secrets, or excessive
    code blocks are transmitted to external LLM providers.
    """
    finding_id: str = Field(..., description="Unique finding identifier.")
    rule_id: str = Field(..., description="Scanner rule or advisory identifier.")
    domain: str = Field(..., description="Canonical cybersecurity domain.")
    title: str = Field(..., max_length=200, description="Short vulnerability summary.")
    severity: Literal["critical", "high", "medium", "low"] = Field(..., description="Severity tier.")
    file: str = Field(..., description="Workspace-relative POSIX file path.")
    line: int | None = Field(default=None, description="Line number if applicable.")
    evidence: str = Field(..., max_length=1000, description="Redacted snippet or advisory statement.")
    confidence: Literal["high", "medium", "low"] = Field(..., description="Confidence tier.")
```

### 3.1 Pre-Dispatch Validation Gate
Before any context is serialized into an LLM prompt, it must pass validation:
1. `len(evidence) <= 1000`: Must not exceed the bounding limit.
2. `redaction_check`: Must not match unmasked credential patterns (AWS `AKIA`, GitHub `ghp_`, private key headers, bearer tokens).

---

## 4. Additive-Only AI Response Contract

The output received from the AI provider is captured in `AIEnrichmentResult`:

```python
class AIEnrichmentResult(BaseModel):
    """
    Additive enrichment generated by AI for a security finding.
    Cannot modify verified scanner evidence, severity, or location.
    """
    finding_id: str = Field(..., description="Identifier of the enriched finding.")
    explanation: str | None = Field(default=None, description="Technical vulnerability explanation.")
    recommendation: str | None = Field(default=None, description="Actionable remediation advice.")
```

### 4.1 Invariant Rules for AI Enrichment
- **Immutability of Evidence:** AI generation must never overwrite, mutate, or reinterpret the verified `evidence`, `file`, `line`, `rule_id`, or `severity` fields.
- **Graceful Fallback:** If the AI provider is unavailable, times out, or produces unparseable output:
  - `finding.explanation` defaults to the scanner's native rule documentation or `None`.
  - `finding.recommendation` defaults to standard remediation guidelines or `None`.
  - The finding remains valid, and the scan report is not blocked.

---

## 5. Standardized Prompt Templates (`prompts.py`)

To ensure deterministic, security-focused responses from the LLM, prompt templates are standardized in `backend/app/ai/prompts.py`:

### 5.1 System Prompt
```python
SYSTEM_PROMPT = (
    "You are an expert Application Security and Code Audit Assistant working on Thread Trace. "
    "Your objective is to provide a concise, technical explanation of a detected security vulnerability "
    "and actionable, code-level remediation steps. "
    "You must rely strictly on the provided sanitized finding metadata. "
    "Do not hallucinate files or context outside the provided finding. "
    "Format your output as structured text containing an Explanation section and a Recommendation section."
)
```

### 5.2 User Prompt Template (`format_finding_prompt`)
```python
def format_finding_prompt(context: AIFindingContext) -> str:
    """Format sanitized finding context into a structured, bounded prompt for the AI model."""
    line_str = f"Line {context.line}" if context.line is not None else "Manifest / File-level"
    return (
        f"Vulnerability Title: {context.title}\n"
        f"Security Domain: {context.domain}\n"
        f"Scanner Rule ID: {context.rule_id}\n"
        f"Severity: {context.severity.upper()}\n"
        f"Location: {context.file} ({line_str})\n"
        f"Confidence: {context.confidence.upper()}\n\n"
        f"Code Context / Evidence:\n"
        f"```\n{context.evidence}\n```\n\n"
        f"Instructions:\n"
        f"1. Explain the underlying security risk and potential exploit scenario in 2-3 sentences.\n"
        f"2. Provide concrete, actionable remediation guidance with code examples where applicable."
    )
```

---

## 6. Developer Roles & Separation of Concerns

| Capability / Responsibility | Dev C (Cybersecurity / DevOps) | Dev B (Backend / Application) |
|---|:---:|:---:|
| **Context Sanitization & Validation** | Owns schema (`AIFindingContext`), redaction gate, length bounding | Uses schema before calling LLM |
| **Prompt Security Templates** | Owns `SYSTEM_PROMPT` & `format_finding_prompt` | Injects prompts into LLM client |
| **Scanner Isolation** | Guarantees scanner adapters do not call AI | Invokes AI asynchronously post-scan |
| **AI Provider Client Implementation** | Stubs interface boundary (`AIService`) | Implements Gemini/OpenAI client & API keys |
| **Finding Database Storage** | — | Updates MongoDB `Finding` model with additive fields |

---

## 7. Verification Criteria

1. **Schema Integrity:** `AIFindingContext` verifies all required fields and rejects invalid severities or missing coordinates.
2. **Bounding Enforcement:** Any evidence string exceeding 1,000 characters is rejected by the model validator.
3. **Credential Detection:** Context creation rejects evidence strings with unmasked credentials.
4. **Additive Integrity:** Mock AI enrichment populates only `explanation` and `recommendation`, leaving scanner evidence intact.
5. **No Filesystem Access:** `AIService` execution executes zero disk I/O or repository reads.
