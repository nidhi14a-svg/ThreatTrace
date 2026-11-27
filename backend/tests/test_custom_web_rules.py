import pytest

from app.scanners.custom_rules.web.command_injection import CommandInjectionShellRule
from app.scanners.custom_rules.web.insecure_deserialization import (
    InsecurePickleLoadRule,
    UnsafeEvalExecRule,
)
from app.scanners.custom_rules.web.path_traversal import PathTraversalOpenRule
from app.scanners.custom_rules.web.sql_injection import SqlInjectionFStringRule


# ============================================================================
# 1. SQL Injection Tests
# ============================================================================


def test_sql_injection_positive():
    """Verify detection of SQL query constructed with f-string interpolation."""
    rule = SqlInjectionFStringRule()
    content = "cursor.execute(f'SELECT * FROM users WHERE email = {email}')\n"
    lines = content.splitlines()

    findings = rule.evaluate("routes/users.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.web.sql-injection-fstring"
    assert findings[0]["severity"] == "high"
    assert findings[0]["canonical_domain"] == "injection"
    assert findings[0]["cwe_id"] == 89


def test_sql_injection_negative_parameterized():
    """Verify parameterized query is not flagged."""
    rule = SqlInjectionFStringRule()
    content = "cursor.execute('SELECT * FROM users WHERE email = %s', (email,))\n"
    lines = content.splitlines()

    findings = rule.evaluate("routes/users.py", content, lines)
    assert len(findings) == 0


# ============================================================================
# 2. Command Injection Tests
# ============================================================================


def test_command_injection_positive():
    """Verify detection of subprocess with shell=True."""
    rule = CommandInjectionShellRule()
    content = "subprocess.Popen(f'ping -c 1 {host}', shell=True)\n"
    lines = content.splitlines()

    findings = rule.evaluate("services/ping.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.web.command-injection-shell"
    assert findings[0]["canonical_domain"] == "injection"


def test_command_injection_negative_list_args():
    """Verify safe subprocess execution with list args and shell=False is not flagged."""
    rule = CommandInjectionShellRule()
    content = "subprocess.run(['ping', '-c', '1', host], shell=False)\n"
    lines = content.splitlines()

    findings = rule.evaluate("services/ping.py", content, lines)
    assert len(findings) == 0


# ============================================================================
# 3. Path Traversal Tests
# ============================================================================


def test_path_traversal_positive():
    """Verify dynamic path concatenation in open() is detected."""
    rule = PathTraversalOpenRule()
    content = "with open(f'/var/uploads/{filename}', 'r') as f:\n    data = f.read()\n"
    lines = content.splitlines()

    findings = rule.evaluate("app/files.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.web.path-traversal-open"
    assert findings[0]["canonical_domain"] == "input_validation"


def test_path_traversal_negative_sanitized():
    """Verify sanitized path with os.path.basename is not flagged."""
    rule = PathTraversalOpenRule()
    content = "safe_name = os.path.basename(filename)\nwith open(safe_name) as f:\n    pass\n"
    lines = content.splitlines()

    findings = rule.evaluate("app/files.py", content, lines)
    assert len(findings) == 0


# ============================================================================
# 4. Insecure Deserialization & Eval Tests
# ============================================================================


def test_pickle_loads_positive():
    """Verify detection of pickle.loads deserialization."""
    rule = InsecurePickleLoadRule()
    content = "obj = pickle.loads(untrusted_payload)\n"
    lines = content.splitlines()

    findings = rule.evaluate("app/data.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.web.insecure-pickle-load"
    assert findings[0]["severity"] == "critical"


def test_pickle_loads_negative_json():
    """Verify safe json.loads is not flagged."""
    rule = InsecurePickleLoadRule()
    content = "obj = json.loads(payload)\n"
    lines = content.splitlines()

    findings = rule.evaluate("app/data.py", content, lines)
    assert len(findings) == 0


def test_unsafe_eval_positive():
    """Verify detection of dynamic eval execution."""
    rule = UnsafeEvalExecRule()
    content = "result = eval(user_expression)\n"
    lines = content.splitlines()

    findings = rule.evaluate("calc.py", content, lines)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "custom.web.unsafe-eval-exec"
    assert findings[0]["severity"] == "critical"
