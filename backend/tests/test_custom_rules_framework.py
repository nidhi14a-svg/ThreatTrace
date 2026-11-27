import pytest
from pathlib import Path
from typing import Any

from app.scanners.base_scanner import BaseScanner, ScannerExecutionResult
from app.scanners.custom_rules.base_rule import BaseCustomRule
from app.scanners.custom_rules.registry import RuleRegistry
from app.scanners.custom_rules.scanner import CustomRulesScanner


class DummyValidRule(BaseCustomRule):
    rule_id: str = "custom.test.dummy-check"
    title: str = "Dummy Check"
    description: str = "A test dummy rule"
    domain: str = "Web Application Security"
    canonical_domain = "injection"
    severity = "high"
    confidence = "medium"
    file_extensions = (".py",)
    cwe_id = 89

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        findings = []
        for idx, line in enumerate(lines, start=1):
            if "DUMMY_VULN" in line:
                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        line=idx,
                        evidence=line.strip(),
                    )
                )
        return findings


class FaultyCrashingRule(BaseCustomRule):
    rule_id: str = "custom.test.faulty-check"
    title: str = "Faulty Check"
    description: str = "Throws unexpected exception"
    domain: str = "Secrets Management"
    canonical_domain = "secrets"
    severity = "critical"
    confidence = "high"
    file_extensions = (".py",)

    def evaluate(self, file_path: str, content: str, lines: list[str]) -> list[dict[str, Any]]:
        raise RuntimeError("Rule evaluation crash")


# ============================================================================
# 1. Rule Registration & Validation
# ============================================================================


def test_registry_registers_valid_rule():
    """Verify registry accepts a valid custom rule."""
    registry = RuleRegistry()
    rule = DummyValidRule()
    registry.register(rule)

    assert registry.get_rule("custom.test.dummy-check") == rule
    assert registry.get_rules_for_extension(".py") == [rule]
    assert registry.get_rules_for_extension(".js") == []
    assert len(registry.get_all_rules()) == 1


def test_registry_rejects_missing_custom_prefix():
    """Verify registry rejects rules without 'custom.' prefix."""
    class BadPrefixRule(DummyValidRule):
        rule_id = "invalid.prefix.rule"

    registry = RuleRegistry()
    with pytest.raises(ValueError, match="must begin with 'custom.'"):
        registry.register(BadPrefixRule())


def test_registry_rejects_invalid_severity():
    """Verify registry rejects rules with invalid severity."""
    class BadSeverityRule(DummyValidRule):
        severity = "super_critical"  # type: ignore

    registry = RuleRegistry()
    with pytest.raises(ValueError, match="invalid severity"):
        registry.register(BadSeverityRule())


def test_registry_rejects_invalid_canonical_domain():
    """Verify registry rejects rules with invalid canonical domain."""
    class BadDomainRule(DummyValidRule):
        canonical_domain = "unknown_domain"  # type: ignore

    registry = RuleRegistry()
    with pytest.raises(ValueError, match="invalid canonical_domain"):
        registry.register(BadDomainRule())


def test_registry_rejects_extension_without_dot():
    """Verify registry rejects file extensions that do not start with a dot."""
    class BadExtRule(DummyValidRule):
        file_extensions = ("py",)

    registry = RuleRegistry()
    with pytest.raises(ValueError, match="must start with a dot"):
        registry.register(BadExtRule())


# ============================================================================
# 2. Fault-Isolated Rule Execution
# ============================================================================


def test_registry_evaluates_file_with_fault_isolation():
    """
    Verify that when one rule crashes during file evaluation,
    other rules execute successfully and findings are collected.
    """
    registry = RuleRegistry()
    valid_rule = DummyValidRule()
    faulty_rule = FaultyCrashingRule()

    registry.register(valid_rule)
    registry.register(faulty_rule)

    content = "x = 1\ny = DUMMY_VULN\nz = 3"
    findings = registry.evaluate_file("app/main.py", content)

    # Valid rule found 1 vulnerability despite faulty rule crashing
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.test.dummy-check"
    assert findings[0]["line"] == 2
    assert findings[0]["evidence"] == "y = DUMMY_VULN"


# ============================================================================
# 3. CustomRulesScanner BaseScanner Integration
# ============================================================================


def test_custom_rules_scanner_satisfies_base_scanner_interface():
    """Verify CustomRulesScanner satisfies BaseScanner contract."""
    scanner = CustomRulesScanner()
    assert isinstance(scanner, BaseScanner)
    assert scanner.name == "custom-rules"
    assert scanner.scanner_name == "custom-rules"


@pytest.mark.anyio
async def test_custom_rules_scanner_workspace_validation(tmp_path: Path):
    """Verify workspace validation (empty string, nonexistent, empty folder)."""
    scanner = CustomRulesScanner()

    # Empty string -> failed
    res = await scanner.scan("")
    assert res.status == "failed"

    # Nonexistent -> skipped
    res = await scanner.scan(str(tmp_path / "does_not_exist"))
    assert res.status == "skipped"
    assert res.findings == []

    # File instead of dir -> failed
    f = tmp_path / "file.txt"
    f.write_text("hello")
    res = await scanner.scan(str(f))
    assert res.status == "failed"

    # Empty directory -> skipped
    empty_d = tmp_path / "empty_dir"
    empty_d.mkdir()
    res = await scanner.scan(str(empty_d))
    assert res.status == "skipped"
    assert res.findings == []


@pytest.mark.anyio
async def test_custom_rules_scanner_finds_vulnerabilities_and_redacts(tmp_path: Path):
    """Verify scanner evaluates files, finds vulnerabilities, and redacts evidence."""
    registry = RuleRegistry()
    registry.register(DummyValidRule())
    scanner = CustomRulesScanner(registry=registry)

    # Setup workspace with target file
    ws = tmp_path / "test_workspace"
    ws.mkdir()
    py_file = ws / "app.py"
    # DUMMY_VULN with raw AWS key in evidence to verify automatic redaction
    py_file.write_text("key = DUMMY_VULN # AKIAIOSFODNN7EXAMPLE\n")

    # Add ignored folder that should not be scanned
    ignored = ws / "node_modules"
    ignored.mkdir()
    (ignored / "sub.py").write_text("bad = DUMMY_VULN\n")

    res = await scanner.scan(str(ws))

    assert res.status == "success"
    assert res.scanner_name == "custom-rules"
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f["file"] == "app.py"
    assert f["line"] == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in f["evidence"]
    assert "AKIA****************" in f["evidence"]
