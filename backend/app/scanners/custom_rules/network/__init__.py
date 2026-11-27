"""Network security custom rules."""

from app.scanners.custom_rules.network.cleartext_http import CleartextHttpEndpointRule
from app.scanners.custom_rules.network.disabled_tls import DisabledTlsVerificationRule
from app.scanners.custom_rules.registry import default_registry

ALL_NETWORK_RULES = [
    DisabledTlsVerificationRule(),
    CleartextHttpEndpointRule(),
]


def register_network_rules() -> None:
    """Register all network security custom rules into default_registry."""
    for rule in ALL_NETWORK_RULES:
        default_registry.register(rule)


__all__ = [
    "DisabledTlsVerificationRule",
    "CleartextHttpEndpointRule",
    "ALL_NETWORK_RULES",
    "register_network_rules",
]
