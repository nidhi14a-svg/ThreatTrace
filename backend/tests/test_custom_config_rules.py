import pytest

from app.scanners.custom_rules.config.debug_mode import DebugModeEnabledRule
from app.scanners.custom_rules.config.insecure_cors import WildcardCorsCredentialsRule
from app.scanners.custom_rules.config.unpinned_dependencies import UnpinnedDependenciesRule


# ============================================================================
# 1. Debug Mode Tests
# ============================================================================


def test_debug_mode_positive():
    """Verify detection of DEBUG = True in application settings."""
    rule = DebugModeEnabledRule()
    content = "DEBUG = True\nSECRET_KEY = 'secret'\n"
    lines = content.splitlines()

    findings = rule.evaluate("app/settings.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.config.debug-mode-enabled"
    assert findings[0]["severity"] == "high"
    assert findings[0]["canonical_domain"] == "configuration"


def test_debug_mode_negative_test_files_and_env():
    """Verify test files and env-based flags are ignored."""
    rule = DebugModeEnabledRule()

    # Ignored because it's a test file
    findings_test = rule.evaluate("tests/test_app.py", "DEBUG = True", ["DEBUG = True"])
    assert len(findings_test) == 0

    # Ignored because it's dynamically read from env
    findings_env = rule.evaluate("app/config.py", "DEBUG = os.getenv('DEBUG', False)", ["DEBUG = os.getenv('DEBUG', False)"])
    assert len(findings_env) == 0


# ============================================================================
# 2. Insecure CORS Tests
# ============================================================================


def test_wildcard_cors_credentials_positive():
    """Verify detection of allow_origins=['*'] combined with allow_credentials=True."""
    rule = WildcardCorsCredentialsRule()
    content = (
        "app.add_middleware(\n"
        "    CORSMiddleware,\n"
        "    allow_origins=['*'],\n"
        "    allow_credentials=True,\n"
        "    allow_methods=['*'],\n"
        ")\n"
    )
    lines = content.splitlines()

    findings = rule.evaluate("app/main.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.config.wildcard-cors-allow-credentials"
    assert findings[0]["canonical_domain"] == "configuration"


def test_wildcard_cors_credentials_negative_safe_origin():
    """Verify explicit origin domain is not flagged."""
    rule = WildcardCorsCredentialsRule()
    content = (
        "app.add_middleware(\n"
        "    CORSMiddleware,\n"
        "    allow_origins=['https://dashboard.example.com'],\n"
        "    allow_credentials=True,\n"
        ")\n"
    )
    lines = content.splitlines()

    findings = rule.evaluate("app/main.py", content, lines)
    assert len(findings) == 0


# ============================================================================
# 3. Unpinned Dependency Tests
# ============================================================================


def test_unpinned_dependencies_positive():
    """Verify detection of wildcard dependencies in requirements.txt."""
    rule = UnpinnedDependenciesRule()
    content = "flask==*\nrequests==2.31.0\n"
    lines = content.splitlines()

    findings = rule.evaluate("requirements.txt", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.config.unpinned-dependency"
    assert findings[0]["line"] == 1
    assert findings[0]["canonical_domain"] == "dependencies"


def test_unpinned_dependencies_negative_pinned():
    """Verify exact pinned versions are not flagged."""
    rule = UnpinnedDependenciesRule()
    content = "flask==2.3.2\nrequests==2.31.0\n"
    lines = content.splitlines()

    findings = rule.evaluate("requirements.txt", content, lines)
    assert len(findings) == 0
