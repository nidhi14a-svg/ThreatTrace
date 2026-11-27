import pytest

from app.core.security import (
    RedactionEngine,
    bound_evidence,
    contains_unmasked_secret,
    redact_secrets,
    sanitize_log,
)


def test_redact_aws_access_key():
    """Verify AWS access key IDs are masked with format-preserving prefix."""
    raw = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    redacted = redact_secrets(raw)

    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "AKIA****************" in redacted


def test_redact_github_pat():
    """Verify GitHub personal access tokens are masked."""
    raw = "GITHUB_PAT = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n"
    redacted = redact_secrets(raw)

    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in redacted
    assert "[REDACTED_GITHUB_TOKEN]" in redacted


def test_redact_private_key_block():
    """Verify multiline private key block is replaced with safe marker."""
    raw = (
        "ssl_key = '''-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1234567890abcdefghijklmnopqrstuvwxyz\n"
        "-----END RSA PRIVATE KEY-----'''\n"
    )
    redacted = redact_secrets(raw)

    assert "MIIEowIBAAKCAQEA0Y1234567890" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted


def test_redact_slack_webhook_and_token():
    """Verify Slack webhook URLs and tokens are sanitized."""
    raw = (
        "hook = 'https://hooks.slack.com/services/T123/B456/XYZ789'\n"
        "token = 'xoxb-1234567890-abcdef123456'\n"
    )
    redacted = redact_secrets(raw)

    assert "T123/B456/XYZ789" not in redacted
    assert "https://hooks.slack.com/services/[REDACTED]" in redacted
    assert "[REDACTED_SLACK_TOKEN]" in redacted


def test_redact_stripe_key():
    """Verify Stripe live API keys are masked."""
    raw_key = "sk_live_" + ("A" * 24)
    raw = f"stripe.api_key = '{raw_key}'\n"
    redacted = redact_secrets(raw)

    assert raw_key not in redacted
    assert "[REDACTED_STRIPE_KEY]" in redacted


def test_redact_bearer_token():
    """Verify Authorization Bearer tokens are masked."""
    raw = "headers = {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.xyz'}"
    redacted = redact_secrets(raw)

    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
    assert "Bearer [REDACTED_BEARER_TOKEN]" in redacted


def test_redact_database_connection_string():
    """Verify database password in connection string is masked with asterisks."""
    raw = "DATABASE_URL = 'postgresql://admin_user:SuperSecretPassword123!@db.internal:5432/maindb'"
    redacted = redact_secrets(raw)

    assert "SuperSecretPassword123!" not in redacted
    assert "postgresql://admin_user:********@db.internal:5432/maindb" in redacted


def test_contains_unmasked_secret():
    """Verify detection of unmasked credentials."""
    assert contains_unmasked_secret("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'") is True
    assert contains_unmasked_secret("AWS_KEY = 'AKIA****************'") is False
    assert contains_unmasked_secret("def calculate_total(a, b): return a + b") is False


def test_sanitize_log():
    """Verify sanitize_log masks secrets in log messages."""
    log_msg = "Failed to connect using token: ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    sanitized = sanitize_log(log_msg)

    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in sanitized
    assert "[REDACTED_GITHUB_TOKEN]" in sanitized


def test_bound_evidence():
    """Verify evidence strings are bounded to max_chars."""
    short_ev = "x = 1"
    assert bound_evidence(short_ev) == "x = 1"

    long_ev = "A" * 1500
    bounded = bound_evidence(long_ev, max_chars=1000)
    assert len(bounded) == 1000
    assert bounded.endswith("...")
