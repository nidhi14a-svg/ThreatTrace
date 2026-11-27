import pytest

from app.scanners.custom_rules.auth.hardcoded_jwt_secret import HardcodedJwtSecretRule
from app.scanners.custom_rules.auth.weak_password_hashing import WeakPasswordHashingRule
from app.scanners.custom_rules.network.cleartext_http import CleartextHttpEndpointRule
from app.scanners.custom_rules.network.disabled_tls import DisabledTlsVerificationRule


# ============================================================================
# 1. Network: Disabled TLS Tests
# ============================================================================


def test_disabled_tls_positive():
    """Verify detection of verify=False in HTTP client requests."""
    rule = DisabledTlsVerificationRule()
    content = "res = requests.get('https://api.internal/data', verify=False)\n"
    lines = content.splitlines()

    findings = rule.evaluate("client.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.network.disabled-tls-verify"
    assert findings[0]["severity"] == "high"
    assert findings[0]["canonical_domain"] == "cryptography"


def test_disabled_tls_negative():
    """Verify default and verify=True requests are not flagged."""
    rule = DisabledTlsVerificationRule()
    content = "res = requests.get('https://api.internal/data', verify=True)\n"
    lines = content.splitlines()

    findings = rule.evaluate("client.py", content, lines)
    assert len(findings) == 0


# ============================================================================
# 2. Network: Cleartext HTTP Tests
# ============================================================================


def test_cleartext_http_positive():
    """Verify hardcoded external cleartext HTTP URL is detected."""
    rule = CleartextHttpEndpointRule()
    content = "AUTH_SERVER = 'http://auth.external-service.com/api/v1'\n"
    lines = content.splitlines()

    findings = rule.evaluate("config.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.network.cleartext-http-endpoint"
    assert findings[0]["canonical_domain"] == "cryptography"


def test_cleartext_http_negative_localhost():
    """Verify localhost / loopback HTTP endpoints are not flagged."""
    rule = CleartextHttpEndpointRule()
    content = "LOCAL_DEV = 'http://localhost:8000/api'\n"
    lines = content.splitlines()

    findings = rule.evaluate("config.py", content, lines)
    assert len(findings) == 0


# ============================================================================
# 3. Auth: Weak Hashing Tests
# ============================================================================


def test_weak_password_hashing_positive():
    """Verify detection of hashlib.md5 in code."""
    rule = WeakPasswordHashingRule()
    content = "pwd_hash = hashlib.md5(password.encode()).hexdigest()\n"
    lines = content.splitlines()

    findings = rule.evaluate("auth/hash.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.auth.weak-md5-sha1-hashing"
    assert findings[0]["severity"] == "high"


def test_weak_password_hashing_negative():
    """Verify SHA-256 or bcrypt is not flagged by weak hashing rule."""
    rule = WeakPasswordHashingRule()
    content = "pwd_hash = hashlib.sha256(data.encode()).hexdigest()\n"
    lines = content.splitlines()

    findings = rule.evaluate("auth/hash.py", content, lines)
    assert len(findings) == 0


# ============================================================================
# 4. Auth: Hardcoded JWT Secret Tests
# ============================================================================


def test_hardcoded_jwt_secret_positive():
    """Verify detection of static string literal in jwt.encode with redaction."""
    rule = HardcodedJwtSecretRule()
    content = "token = jwt.encode(payload, 'super_secret_jwt_key_99', algorithm='HS256')\n"
    lines = content.splitlines()

    findings = rule.evaluate("auth/tokens.py", content, lines)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "custom.auth.hardcoded-jwt-secret"
    assert f["severity"] == "critical"
    assert f["canonical_domain"] == "authentication"
    assert "super_secret_jwt_key_99" not in f["evidence"]
    assert "********" in f["evidence"]


def test_hardcoded_jwt_secret_negative_env():
    """Verify environment lookup for JWT secret is not flagged."""
    rule = HardcodedJwtSecretRule()
    content = "token = jwt.encode(payload, os.getenv('JWT_SECRET'), algorithm='HS256')\n"
    lines = content.splitlines()

    findings = rule.evaluate("auth/tokens.py", content, lines)
    assert len(findings) == 0
