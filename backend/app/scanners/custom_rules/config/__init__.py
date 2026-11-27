"""Configuration and dependency custom rules."""

from app.scanners.custom_rules.config.debug_mode import DebugModeEnabledRule
from app.scanners.custom_rules.config.insecure_cors import WildcardCorsCredentialsRule
from app.scanners.custom_rules.config.unpinned_dependencies import UnpinnedDependenciesRule
from app.scanners.custom_rules.registry import default_registry

ALL_CONFIG_RULES = [
    DebugModeEnabledRule(),
    WildcardCorsCredentialsRule(),
    UnpinnedDependenciesRule(),
]


def register_config_rules() -> None:
    """Register all configuration custom rules into default_registry."""
    for rule in ALL_CONFIG_RULES:
        default_registry.register(rule)


__all__ = [
    "DebugModeEnabledRule",
    "WildcardCorsCredentialsRule",
    "UnpinnedDependenciesRule",
    "ALL_CONFIG_RULES",
    "register_config_rules",
]
