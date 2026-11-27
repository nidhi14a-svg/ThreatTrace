"""
Custom security rules framework for Thread Trace.

Provides modular rule definitions, registry, and scanner adapter for
project-specific cybersecurity checks across all five domains.
"""

from app.scanners.custom_rules.auth import ALL_AUTH_RULES, register_auth_rules
from app.scanners.custom_rules.base_rule import BaseCustomRule
from app.scanners.custom_rules.config import ALL_CONFIG_RULES, register_config_rules
from app.scanners.custom_rules.network import ALL_NETWORK_RULES, register_network_rules
from app.scanners.custom_rules.registry import RuleRegistry, default_registry
from app.scanners.custom_rules.scanner import CustomRulesScanner
from app.scanners.custom_rules.secrets import ALL_SECRETS_RULES, register_secrets_rules
from app.scanners.custom_rules.web import ALL_WEB_RULES, register_web_rules

ALL_CUSTOM_RULES = (
    ALL_SECRETS_RULES
    + ALL_WEB_RULES
    + ALL_NETWORK_RULES
    + ALL_AUTH_RULES
    + ALL_CONFIG_RULES
)


def register_all_custom_rules(registry: RuleRegistry | None = None) -> None:
    """Register all modular custom security rules across all five domains."""
    target_registry = registry or default_registry
    for rule in ALL_CUSTOM_RULES:
        target_registry.register(rule)


__all__ = [
    "BaseCustomRule",
    "RuleRegistry",
    "default_registry",
    "CustomRulesScanner",
    "ALL_CUSTOM_RULES",
    "register_all_custom_rules",
    "register_secrets_rules",
    "register_web_rules",
    "register_network_rules",
    "register_auth_rules",
    "register_config_rules",
]
