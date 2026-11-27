"""Web security custom rules."""

from app.scanners.custom_rules.registry import default_registry
from app.scanners.custom_rules.web.command_injection import CommandInjectionShellRule
from app.scanners.custom_rules.web.insecure_deserialization import (
    InsecurePickleLoadRule,
    UnsafeEvalExecRule,
)
from app.scanners.custom_rules.web.path_traversal import PathTraversalOpenRule
from app.scanners.custom_rules.web.sql_injection import SqlInjectionFStringRule

ALL_WEB_RULES = [
    SqlInjectionFStringRule(),
    CommandInjectionShellRule(),
    PathTraversalOpenRule(),
    InsecurePickleLoadRule(),
    UnsafeEvalExecRule(),
]


def register_web_rules() -> None:
    """Register all web security custom rules into default_registry."""
    for rule in ALL_WEB_RULES:
        default_registry.register(rule)


__all__ = [
    "SqlInjectionFStringRule",
    "CommandInjectionShellRule",
    "PathTraversalOpenRule",
    "InsecurePickleLoadRule",
    "UnsafeEvalExecRule",
    "ALL_WEB_RULES",
    "register_web_rules",
]
