import pytest
from pydantic import ValidationError

from app.ai.ai_service import (
    AIFindingContext,
    AIEnrichmentResult,
    AIService,
    create_ai_finding_context,
)
from app.ai.prompts import SYSTEM_PROMPT, format_finding_prompt


# ============================================================================
# 1. AIFindingContext Model & Validation Invariants
# ============================================================================


def test_ai_finding_context_valid_instantiation():
    """Verify that a valid sanitized finding context instantiates correctly."""
    context = AIFindingContext(
        finding_id="find_12345",
        rule_id="bandit.B608",
        domain="Web Application Security",
        title="Possible SQL injection vector",
        severity="high",
        file="backend/app/routes/search.py",
        line=42,
        evidence="cursor.execute(f'SELECT * FROM users WHERE email = {email}')",
        confidence="high",
    )

    assert context.finding_id == "find_12345"
    assert context.rule_id == "bandit.B608"
    assert context.domain == "Web Application Security"
    assert context.severity == "high"
    assert context.file == "backend/app/routes/search.py"
    assert context.line == 42
    assert "SELECT * FROM users" in context.evidence
    assert context.confidence == "high"


def test_ai_finding_context_rejects_evidence_longer_than_1000_chars():
    """Verify that evidence exceeding 1,000 characters is rejected by validator."""
    huge_evidence = "SELECT * FROM data WHERE x = " + ("1 " * 500)
    assert len(huge_evidence) > 1000

    with pytest.raises(ValidationError) as exc_info:
        AIFindingContext(
            finding_id="find_test",
            rule_id="test.rule",
            domain="General",
            title="Test",
            severity="medium",
            file="app/main.py",
            line=1,
            evidence=huge_evidence,
            confidence="medium",
        )

    assert "at most 1000 characters" in str(exc_info.value) or "exceeds maximum allowed" in str(exc_info.value)


def test_ai_finding_context_rejects_unredacted_aws_key():
    """Verify that evidence with unmasked AWS credentials is rejected."""
    unredacted = "AWS_SECRET = 'AKIAIOSFODNN7EXAMPLE'"

    with pytest.raises(ValidationError) as exc_info:
        AIFindingContext(
            finding_id="find_test",
            rule_id="secrets.aws",
            domain="Secrets Management",
            title="AWS Key Leak",
            severity="critical",
            file="config.py",
            line=10,
            evidence=unredacted,
            confidence="high",
        )

    assert "Unredacted AWS access key detected" in str(exc_info.value)


def test_ai_finding_context_rejects_unredacted_github_token():
    """Verify that evidence with unmasked GitHub PATs is rejected."""
    unredacted = "token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'"

    with pytest.raises(ValidationError) as exc_info:
        AIFindingContext(
            finding_id="find_test",
            rule_id="secrets.github",
            domain="Secrets Management",
            title="GitHub Token",
            severity="critical",
            file="auth.py",
            line=15,
            evidence=unredacted,
            confidence="high",
        )

    assert "Unredacted GitHub personal access token detected" in str(exc_info.value)


def test_ai_finding_context_rejects_unredacted_private_key():
    """Verify that evidence with unmasked private key blocks is rejected."""
    unredacted = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"

    with pytest.raises(ValidationError) as exc_info:
        AIFindingContext(
            finding_id="find_test",
            rule_id="secrets.key",
            domain="Secrets Management",
            title="Private Key Leak",
            severity="critical",
            file="server.key",
            line=1,
            evidence=unredacted,
            confidence="high",
        )

    assert "Unredacted private key block detected" in str(exc_info.value)


# ============================================================================
# 2. create_ai_finding_context Helper & Automatic Sanitization
# ============================================================================


def test_create_ai_finding_context_applies_redaction_and_bounding():
    """Verify create_ai_finding_context automatically sanitizes unredacted keys and bounds length."""
    raw_finding = {
        "id": "find_auto_1",
        "rule_id": "semgrep.secret",
        "domain": "Secrets Management",
        "title": "Hardcoded Key",
        "severity": "CRITICAL",
        "file": "app/config.py",
        "line": 12,
        # Contains raw AWS key and exceeds 1,000 characters
        "evidence": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE' # " + ("padding " * 200),
        "confidence": "HIGH",
        # Extraneous fields that must be stripped from AI context
        "full_file_source": "print('entire repository here...')",
        "internal_env": {"DB_PASS": "secret"},
        "ast_dump": "<AST tree node>",
    }

    context = create_ai_finding_context(raw_finding)

    assert context.finding_id == "find_auto_1"
    assert context.severity == "critical"
    assert context.confidence == "high"
    assert len(context.evidence) <= 1000
    assert "AKIAIOSFODNN7EXAMPLE" not in context.evidence
    assert "AKIA****************" in context.evidence

    # Verify extraneous fields were stripped
    context_dict = context.model_dump()
    assert "full_file_source" not in context_dict
    assert "internal_env" not in context_dict
    assert "ast_dump" not in context_dict


def test_create_ai_finding_context_defaults_missing_fields_safely():
    """Verify graceful handling when optional or raw finding fields are missing."""
    sparse_finding = {
        "file": "package.json",
        "evidence": "lodash prototype pollution",
    }

    context = create_ai_finding_context(sparse_finding, finding_id="find_fallback")

    assert context.finding_id == "find_fallback"
    assert context.severity == "medium"
    assert context.confidence == "medium"
    assert context.line is None
    assert context.domain == "General Security"
    assert context.file == "package.json"


# ============================================================================
# 3. Prompt Formatting Contract
# ============================================================================


def test_format_finding_prompt_includes_only_sanitized_fields():
    """Verify format_finding_prompt generates structured text with only allowed fields."""
    context = AIFindingContext(
        finding_id="find_99",
        rule_id="semgrep.command-injection",
        domain="Web Application Security",
        title="Unescaped subprocess call",
        severity="critical",
        file="backend/app/services/worker.py",
        line=88,
        evidence="subprocess.Popen(f'ping -c 1 {host}', shell=True)",
        confidence="high",
    )

    prompt = format_finding_prompt(context)

    assert "Vulnerability Title: Unescaped subprocess call" in prompt
    assert "Security Domain: Web Application Security" in prompt
    assert "Scanner Rule ID: semgrep.command-injection" in prompt
    assert "Severity: CRITICAL" in prompt
    assert "Location: backend/app/services/worker.py (Line 88)" in prompt
    assert "subprocess.Popen" in prompt
    assert "Instructions:" in prompt


def test_format_finding_prompt_manifest_level_line_representation():
    """Verify manifest-level findings (line: None) render gracefully."""
    context = AIFindingContext(
        finding_id="find_dep",
        rule_id="GHSA-xxxx-yyyy",
        domain="Dependency Security",
        title="Vulnerable Jinja2",
        severity="high",
        file="requirements.txt",
        line=None,
        evidence="Dependency 'jinja2' version '2.11.2' matches advisory GHSA-xxxx-yyyy.",
        confidence="medium",
    )

    prompt = format_finding_prompt(context)
    assert "Location: requirements.txt (Manifest / File-level)" in prompt


def test_system_prompt_defines_assistant_role_and_boundaries():
    """Verify SYSTEM_PROMPT contains security assistant role and anti-hallucination constraint."""
    assert "Application Security and Code Audit Assistant" in SYSTEM_PROMPT
    assert "strictly on the provided sanitized finding metadata" in SYSTEM_PROMPT


# ============================================================================
# 4. AIService Boundary & Additive-Only AI Enrichment
# ============================================================================


@pytest.mark.anyio
async def test_ai_service_enrich_finding_is_additive_only():
    """
    Verify AIService produces additive explanation and recommendation
    without modifying verified scanner evidence.
    """
    service = AIService()
    context = AIFindingContext(
        finding_id="find_x1",
        rule_id="bandit.B501",
        domain="Web Application Security",
        title="Disabled SSL verification",
        severity="medium",
        file="app/client.py",
        line=25,
        evidence="requests.get(url, verify=False)",
        confidence="high",
    )

    result = await service.enrich_finding(context)

    assert isinstance(result, AIEnrichmentResult)
    assert result.finding_id == "find_x1"
    assert result.explanation is not None
    assert "bandit.B501" in result.explanation
    assert result.recommendation is not None
    assert "Apply secure coding standards" in result.recommendation

    # Verify context fields were not mutated
    assert context.file == "app/client.py"
    assert context.line == 25
    assert context.evidence == "requests.get(url, verify=False)"
    assert context.severity == "medium"
