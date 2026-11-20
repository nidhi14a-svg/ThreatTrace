from app.schemas.finding import Finding


def test_finding_schema_accepts_optional_line():
    finding = Finding(
        id="finding-001",
        domain="Secrets Management",
        rule_id="SECRET-001",
        title="Possible hardcoded API key",
        severity="high",
        file="src/config.py",
        evidence="API_KEY = [REDACTED]",
        confidence="medium",
        tool="secret-scanner",
    )
    assert finding.line is None
