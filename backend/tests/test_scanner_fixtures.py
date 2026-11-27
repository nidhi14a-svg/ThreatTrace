"""End-to-end scanner fixture evaluation and normalized-result assertions.

Validates:
- Custom rules scanner execution across vulnerable fixtures
- Complete 5-domain detection coverage (secrets, web, network, auth, config)
- Normalized finding schema compliance (Finding Pydantic model)
- Coordinate mapping and evidence bounding
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.scanners.custom_rules import default_registry, register_all_custom_rules
from app.scanners.custom_rules.scanner import CustomRulesScanner
from app.scanners.normalizer import normalize_scanner_result

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
VULNERABLE_DIR = FIXTURES_DIR / "vulnerable"


@pytest.fixture(scope="module", autouse=True)
def setup_rules():
    """Ensure all modular custom rules are registered."""
    register_all_custom_rules(default_registry)


@pytest.mark.anyio
async def test_custom_rules_vulnerable_fixtures_detection() -> None:
    """Verify custom rules scanner detects all expected vulnerabilities in synthetic fixtures."""
    scanner = CustomRulesScanner(registry=default_registry)
    result = await scanner.scan(str(VULNERABLE_DIR))

    assert result.status == "success"
    assert result.error is None
    assert len(result.findings) >= 12, f"Expected at least 12 findings, got {len(result.findings)}"

    rule_ids = {f.get("rule_id") for f in result.findings}

    # Secrets domain detections
    assert "custom.secrets.hardcoded-api-key" in rule_ids
    assert "custom.secrets.hardcoded-password" in rule_ids
    assert "custom.secrets.private-key-material" in rule_ids

    # Web domain detections
    assert "custom.web.sql-injection-fstring" in rule_ids
    assert "custom.web.command-injection-shell" in rule_ids
    assert "custom.web.path-traversal-open" in rule_ids
    assert "custom.web.insecure-pickle-load" in rule_ids
    assert "custom.web.unsafe-eval-exec" in rule_ids

    # Network domain detections
    assert "custom.network.disabled-tls-verify" in rule_ids
    assert "custom.network.cleartext-http-endpoint" in rule_ids

    # Auth domain detections
    assert "custom.auth.weak-md5-sha1-hashing" in rule_ids
    assert "custom.auth.hardcoded-jwt-secret" in rule_ids

    # Config domain detections
    assert "custom.config.debug-mode-enabled" in rule_ids
    assert "custom.config.wildcard-cors-allow-credentials" in rule_ids
    assert "custom.config.unpinned-dependency" in rule_ids


@pytest.mark.anyio
async def test_vulnerable_findings_normalization_schema_compliance() -> None:
    """Verify all findings from vulnerable fixtures normalize into canonical Finding models."""
    scanner = CustomRulesScanner(registry=default_registry)
    result = await scanner.scan(str(VULNERABLE_DIR))

    normalized_findings = normalize_scanner_result(result)
    assert len(normalized_findings) == len(result.findings)

    for finding in normalized_findings:
        # Schema assertions
        assert finding.id.startswith("find_") or len(finding.id) > 0
        assert finding.tool == "custom-rules"
        assert finding.severity in ("critical", "high", "medium", "low")
        assert finding.confidence in ("high", "medium", "low")
        assert "\\" not in finding.file, "File paths must use normalized forward slashes"
        assert not finding.file.startswith("./"), "Relative paths must not start with ./"
        assert len(finding.evidence) <= 1000, "Evidence must be bounded to 1000 chars"
        assert "AKIA1234567890EXAMPLE" not in finding.evidence, "Secrets must be redacted"
