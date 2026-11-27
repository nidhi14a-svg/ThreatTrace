"""Tests verifying container security boundaries, privileges, and resource limits.

Validates:
- Non-root user (UID 10001)
- Read-only root filesystem and tmpfs write isolation
- Dropped capabilities (ALL) and no-new-privileges
- Internal network air-gapping (scanner cannot access mongodb)
- Explicit resource ceilings (CPU 2.0, RAM 1536M, swap disabled, PIDs 100)
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

COMPOSE_FILE = Path(__file__).resolve().parent.parent.parent / "docker-compose.yml"


@pytest.fixture
def compose_data() -> dict:
    """Parse docker-compose.yml."""
    assert COMPOSE_FILE.exists()
    return yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))


def test_scanner_container_unprivileged_security_flags(compose_data: dict) -> None:
    """Verify scanner container runs with zero root privileges and read-only rootfs."""
    scanner = compose_data["services"]["scanner"]

    # Non-root UID
    assert scanner.get("user") == "10001:10001"

    # Read-only root filesystem
    assert scanner.get("read_only") is True

    # Scratch tmpfs
    tmpfs = scanner.get("tmpfs", [])
    assert any("/tmp" in entry for entry in tmpfs)

    # Capabilities dropped
    assert "ALL" in scanner.get("cap_drop", [])

    # No new privileges
    assert "no-new-privileges:true" in scanner.get("security_opt", [])


def test_network_isolation_scanner_isolated_from_mongodb(compose_data: dict) -> None:
    """Verify scanner is attached exclusively to scanner-net and cannot route to mongodb."""
    scanner_nets = compose_data["services"]["scanner"].get("networks", [])
    mongodb_nets = compose_data["services"]["mongodb"].get("networks", [])

    assert scanner_nets == ["scanner-net"]
    assert mongodb_nets == ["db-net"]

    # Both networks must be internal
    networks = compose_data.get("networks", {})
    assert networks["scanner-net"].get("internal") is True
    assert networks["db-net"].get("internal") is True


def test_resource_limits_explicitly_bounded(compose_data: dict) -> None:
    """Verify scanner container enforces hard resource ceilings."""
    scanner = compose_data["services"]["scanner"]

    assert float(scanner.get("cpus", 0)) <= 2.0
    assert scanner.get("mem_limit") in ("1536m", "1536M")
    assert scanner.get("memswap_limit") == scanner.get("mem_limit"), "Swap must be disabled"
    assert int(scanner.get("pids_limit", 0)) <= 100
