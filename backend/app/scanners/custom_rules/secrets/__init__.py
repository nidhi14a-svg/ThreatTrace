"""Secrets management custom rules."""

from app.scanners.custom_rules.registry import default_registry
from app.scanners.custom_rules.secrets.connection_strings import DatabaseConnectionStringRule
from app.scanners.custom_rules.secrets.hardcoded_credentials import (
    HardcodedApiKeyRule,
    HardcodedPasswordRule,
    PrivateKeyMaterialRule,
)

ALL_SECRETS_RULES = [
    HardcodedApiKeyRule(),
    HardcodedPasswordRule(),
    PrivateKeyMaterialRule(),
    DatabaseConnectionStringRule(),
]


def register_secrets_rules() -> None:
    """Register all secrets management custom rules into default_registry."""
    for rule in ALL_SECRETS_RULES:
        default_registry.register(rule)


__all__ = [
    "HardcodedApiKeyRule",
    "HardcodedPasswordRule",
    "PrivateKeyMaterialRule",
    "DatabaseConnectionStringRule",
    "ALL_SECRETS_RULES",
    "register_secrets_rules",
]
