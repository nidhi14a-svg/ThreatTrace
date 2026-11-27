"""Tests verifying secret redaction, log sanitization, and evidence bounding.

Validates:
- Structured token masking (AWS, GitHub, Slack, Stripe, Bearer)
- Unstructured credential masking (database passwords)
- Multi-line cryptographic private key block obliteration
- Log handler sanitization
- Finding coordinate and metadata preservation during redaction
- Invariant: zero unmasked secrets enter reports or AI prompts
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from app.core.security import (
    RedactionEngine,
    bound_evidence,
    contains_unmasked_secret,
    redact_secrets,
    sanitize_log,
)
from app.schemas.finding import Finding


class TestSecretRedactionVerification:
    """Test suite verifying Task 5.5 requirements."""

    def test_aws_access_key_format_preserving_mask(self) -> None:
        """Verify AWS Access Key ID retains AKIA prefix and masks 16 alphanumeric characters."""
        raw_token = "AKIAIOSFODNN7EXAMPLE"
        snippet = f'aws_key = "{raw_token}"'
        redacted = redact_secrets(snippet)

        assert raw_token not in redacted
        assert "AKIA****************" in redacted
        assert contains_unmasked_secret(redacted) is False

    def test_github_pat_mask(self) -> None:
        """Verify GitHub personal access tokens are replaced with safe marker."""
        raw_token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
        snippet = f'gh_token = "{raw_token}"'
        redacted = redact_secrets(snippet)

        assert raw_token not in redacted
        assert "[REDACTED_GITHUB_TOKEN]" in redacted
        assert contains_unmasked_secret(redacted) is False

    def test_multiline_private_key_obliteration(self) -> None:
        """Verify entire RSA private key blocks are replaced with single marker."""
        raw_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y3v7X5V5q8L7o1Q8+8cK9xZ1Y2X3W4V5U6T7S8R9Q0P1O2N\n"
            "3M4L5K6J7I8H9G0F1E2D3C4B5A6Z7Y8X9W0V1U2T3S4R5Q6P7O8N9M0L1K2J3I4H\n"
            "-----END RSA PRIVATE KEY-----"
        )
        snippet = f'private_key = """{raw_key}"""'
        redacted = redact_secrets(snippet)

        assert "MIIEowIBAAKCAQEA" not in redacted
        assert "[REDACTED_PRIVATE_KEY]" in redacted
        assert contains_unmasked_secret(redacted) is False

    def test_database_password_in_connection_uri(self) -> None:
        """Verify password inside database connection string is masked with asterisks."""
        raw_uri = "postgres://dbadmin:SuperSecretPassword123!@postgres.internal:5432/production"
        redacted = redact_secrets(f'DATABASE_URL = "{raw_uri}"')

        assert "SuperSecretPassword123!" not in redacted
        assert "postgres://dbadmin:********@postgres.internal:5432/production" in redacted

    def test_stripe_live_key_mask(self) -> None:
        """Verify Stripe live API keys are masked."""
        raw_key = "sk_" + "live_" + "FAKE" + "51Abcdefghijklmnopqrstuvwxy"
        redacted = redact_secrets(f'stripe_api_key = "{raw_key}"')

        assert raw_key not in redacted
        assert "[REDACTED_STRIPE_KEY]" in redacted

    def test_slack_webhook_and_token_mask(self) -> None:
        """Verify Slack webhooks and bot tokens are masked."""
        raw_webhook = "https://hooks.slack.com/services/T00000000/B00000000/" + ("X" * 24)
        raw_token = "xoxb-" + "1234567890-1234567890123-abcdefghijklmnopqrstuvwx"
        text = f"webhook={raw_webhook}\ntoken={raw_token}"
        redacted = redact_secrets(text)

        assert "XXXXXXXXXXXXXXXXXXXXXXXX" not in redacted
        assert "https://hooks.slack.com/services/[REDACTED]" in redacted
        assert raw_token not in redacted
        assert "[REDACTED_SLACK_TOKEN]" in redacted

    def test_bearer_token_mask(self) -> None:
        """Verify Authorization Bearer token bodies are masked."""
        raw_bearer = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisTokenBody"
        redacted = redact_secrets(raw_bearer)

        assert "doNotLeakThisTokenBody" not in redacted
        assert "Authorization: Bearer [REDACTED_BEARER_TOKEN]" in redacted

    def test_log_sanitization_masks_credentials(self) -> None:
        """Verify sanitize_log prevents credentials from entering log output."""
        msg = "Database connection error using uri postgres://admin:VerySecretPass999@localhost/app"
        clean_log = sanitize_log(msg)

        assert "VerySecretPass999" not in clean_log
        assert "postgres://admin:********@localhost/app" in clean_log

    def test_evidence_bounding_respects_max_chars(self) -> None:
        """Verify evidence longer than max_chars is safely truncated."""
        large_code = "print('hello'); " * 200  # ~3200 chars
        bounded = bound_evidence(large_code, max_chars=1000)

        assert len(bounded) == 1000
        assert bounded.endswith("...")

    def test_metadata_and_coordinates_preserved_in_finding(self) -> None:
        """Verify finding metadata (rule_id, file, line) is preserved while evidence is redacted."""
        raw_secret_evidence = "AWS_SECRET = 'AKIAIOSFODNN7EXAMPLE'"
        redacted_evidence = bound_evidence(redact_secrets(raw_secret_evidence), max_chars=1000)

        finding = Finding(
            id="f-secrets-001",
            domain="Secrets Management",
            rule_id="custom.secrets.hardcoded-api-key",
            title="Hardcoded AWS Access Key ID",
            severity="high",
            file="src/config/aws.py",
            line=42,
            evidence=redacted_evidence,
            confidence="high",
            tool="custom-rules",
        )

        assert finding.rule_id == "custom.secrets.hardcoded-api-key"
        assert finding.file == "src/config/aws.py"
        assert finding.line == 42
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence
        assert "AKIA****************" in finding.evidence
        assert contains_unmasked_secret(finding.evidence) is False
