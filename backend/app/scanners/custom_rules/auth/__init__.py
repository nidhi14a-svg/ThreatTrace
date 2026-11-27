"""Authentication and access control custom rules."""

from app.scanners.custom_rules.auth.hardcoded_jwt_secret import HardcodedJwtSecretRule
from app.scanners.custom_rules.auth.weak_password_hashing import WeakPasswordHashingRule
from app.scanners.custom_rules.registry import default_registry

ALL_AUTH_RULES = [
    WeakPasswordHashingRule(),
    HardcodedJwtSecretRule(),
]


def register_auth_rules() -> None:
    """Register all authentication custom rules into default_registry."""
    for rule in ALL_AUTH_RULES:
        default_registry.register(rule)


__all__ = [
    "WeakPasswordHashingRule",
    "HardcodedJwtSecretRule",
    "ALL_AUTH_RULES",
    "register_auth_rules",
]
