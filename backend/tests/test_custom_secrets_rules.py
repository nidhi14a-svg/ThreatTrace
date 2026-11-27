import pytest

from app.scanners.custom_rules.secrets.connection_strings import DatabaseConnectionStringRule
from app.scanners.custom_rules.secrets.hardcoded_credentials import (
    HardcodedApiKeyRule,
    HardcodedPasswordRule,
    PrivateKeyMaterialRule,
)


# ============================================================================
# 1. Hardcoded API Key Tests
# ============================================================================


def test_hardcoded_api_key_positive():
    """Verify detection of real hardcoded API key with redaction."""
    rule = HardcodedApiKeyRule()
    fake_key = "sk_live_" + "abcdef1234567890abcdef1234567890"
    content = f"api_key = '{fake_key}'\n"
    lines = content.splitlines()

    findings = rule.evaluate("config.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.secrets.hardcoded-api-key"
    assert findings[0]["line"] == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["canonical_domain"] == "secrets"


def test_hardcoded_api_key_negative_placeholders_and_env():
    """Verify placeholders and environment lookups are not flagged as false positives."""
    rule = HardcodedApiKeyRule()
    safe_samples = [
        "api_key = os.getenv('API_KEY')",
        "api_key = 'YOUR_API_KEY'",
        "api_key = 'placeholder'",
        "api_key = ''",
        "api_key = 'test_key_123456'",
    ]
    for sample in safe_samples:
        findings = rule.evaluate("config.py", sample, sample.splitlines())
        assert len(findings) == 0, f"Expected 0 findings for safe sample: {sample}"


# ============================================================================
# 2. Database Connection String Tests
# ============================================================================


def test_database_connection_string_positive():
    """Verify detection of database connection string with embedded password."""
    rule = DatabaseConnectionStringRule()
    content = "DATABASE_URL = 'postgresql://dbadmin:SuperSecretPass999!@db.internal:5432/appdb'\n"
    lines = content.splitlines()

    findings = rule.evaluate("settings.py", content, lines)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "custom.secrets.database-connection-string"
    assert f["severity"] == "critical"
    assert f["canonical_domain"] == "secrets"
    assert "SuperSecretPass999!" not in f["evidence"]
    assert "********" in f["evidence"]


def test_database_connection_string_negative_placeholders():
    """Verify template/placeholder connection strings are not flagged."""
    rule = DatabaseConnectionStringRule()
    safe_samples = [
        "DATABASE_URL = 'postgresql://user:password@localhost:5432/dev'",
        "DATABASE_URL = 'mongodb://app:changeme@localhost:27017/test'",
        "DATABASE_URL = os.environ.get('DATABASE_URL')",
    ]
    for sample in safe_samples:
        findings = rule.evaluate("settings.py", sample, sample.splitlines())
        assert len(findings) == 0, f"Expected 0 findings for safe sample: {sample}"


# ============================================================================
# 3. Hardcoded Password Tests
# ============================================================================


def test_hardcoded_password_positive():
    """Verify detection of cleartext password assignments."""
    rule = HardcodedPasswordRule()
    content = "admin_password = 'ProdPassword2026!xyz'\n"
    lines = content.splitlines()

    findings = rule.evaluate("auth.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.secrets.hardcoded-password"
    assert findings[0]["severity"] == "high"


def test_hardcoded_password_negative_placeholders():
    """Verify placeholder passwords and env reads are ignored."""
    rule = HardcodedPasswordRule()
    safe_samples = [
        "password = 'changeme'",
        "password = 'admin'",
        "password = ''",
        "password = os.getenv('ADMIN_PASSWORD')",
    ]
    for sample in safe_samples:
        findings = rule.evaluate("auth.py", sample, sample.splitlines())
        assert len(findings) == 0


# ============================================================================
# 4. Private Key Material Tests
# ============================================================================


def test_private_key_material_positive():
    """Verify detection of embedded private key headers."""
    rule = PrivateKeyMaterialRule()
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
    lines = content.splitlines()

    findings = rule.evaluate("server.pem", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.secrets.private-key-material"
    assert findings[0]["severity"] == "critical"
    assert findings[0]["evidence"] == "[REDACTED_PRIVATE_KEY_HEADER]"
