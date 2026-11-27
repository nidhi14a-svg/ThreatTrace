"""Tests verifying the Zero-Execution Invariant on analyzed repositories.

Validates:
- Uploaded source code, build hooks, and package scripts are never executed
- setup.py, Makefile, and package.json lifecycle scripts remain inert text
- Scanners use static AST parsing and regex; no dynamic imports occur
- Injected tripwire files verify zero execution throughout the scan lifecycle
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from app.scanners.custom_rules import default_registry, register_all_custom_rules
from app.scanners.custom_rules.scanner import CustomRulesScanner


@pytest.fixture(scope="module", autouse=True)
def setup_rules():
    """Ensure all modular custom rules are registered."""
    register_all_custom_rules(default_registry)


@pytest.mark.anyio
async def test_uploaded_repository_scripts_are_never_executed() -> None:
    """
    Verify that hostile build scripts containing execution tripwires are never executed.

    Tripwires:
    1. setup.py: writes tripwire_setup.txt if executed.
    2. __init__.py: writes tripwire_init.txt if imported.
    3. package.json: preinstall hook writes tripwire_npm.txt if invoked.
    4. Makefile: default target writes tripwire_make.txt if built.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        workspace = Path(tmp_dir)

        tripwire_setup = workspace / "tripwire_setup.txt"
        tripwire_init = workspace / "tripwire_init.txt"
        tripwire_npm = workspace / "tripwire_npm.txt"
        tripwire_make = workspace / "tripwire_make.txt"

        # 1. Hostile setup.py
        setup_py = workspace / "setup.py"
        setup_py.write_text(
            f"import os\nopen(r'{tripwire_setup}', 'w').write('EXECUTED')\n",
            encoding="utf-8",
        )

        # 2. Hostile __init__.py
        init_py = workspace / "__init__.py"
        init_py.write_text(
            f"import os\nopen(r'{tripwire_init}', 'w').write('EXECUTED')\n",
            encoding="utf-8",
        )

        # 3. Hostile package.json
        package_json = workspace / "package.json"
        package_json.write_text(
            f'{{"name": "hostile", "scripts": {{"preinstall": "echo EXECUTED > {tripwire_npm}"}}}}',
            encoding="utf-8",
        )

        # 4. Hostile Makefile
        makefile = workspace / "Makefile"
        makefile.write_text(
            f"all:\n\techo EXECUTED > {tripwire_make}\n",
            encoding="utf-8",
        )

        # 5. Add a standard python file with custom rule detection target
        app_py = workspace / "app.py"
        app_py.write_text(
            'API_KEY = "AKIA1234567890EXAMPLE"\nDEBUG = True\n',
            encoding="utf-8",
        )

        # Run custom rules scanner over the workspace
        scanner = CustomRulesScanner(registry=default_registry)
        result = await scanner.scan(str(workspace))

        # Assert scanner completed and found the vulnerable patterns
        assert result.status == "success"
        assert len(result.findings) >= 2

        # ZERO EXECUTION INVARIANT ASSERTIONS:
        # None of the tripwire files must exist!
        assert not tripwire_setup.exists(), "CRITICAL: setup.py was executed!"
        assert not tripwire_init.exists(), "CRITICAL: __init__.py was executed/imported!"
        assert not tripwire_npm.exists(), "CRITICAL: package.json script was executed!"
        assert not tripwire_make.exists(), "CRITICAL: Makefile was executed!"
