"""
Rule registry, validation, and execution manager for custom security rules.

Manages registration, metadata validation, extension-based rule dispatch,
and fault-isolated execution across all project-specific security rules.
"""

import logging
from pathlib import Path
from typing import Any

from app.scanners.base_scanner import BaseScanner
from app.scanners.custom_rules.base_rule import BaseCustomRule

logger = logging.getLogger(__name__)

VALID_CANONICAL_DOMAINS = {
    "injection",
    "authentication",
    "authorization",
    "cryptography",
    "secrets",
    "dependencies",
    "configuration",
    "input_validation",
    "logging",
    "other",
}

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_CONFIDENCES = {"high", "medium", "low"}


class RuleRegistry:
    """
    Central registry for custom security detection rules.

    Provides rule registration with strict validation, extension-based index mapping,
    and safe execution with error isolation.
    """

    def __init__(self) -> None:
        self._rules_by_id: dict[str, BaseCustomRule] = {}
        self._rules_by_ext: dict[str, list[BaseCustomRule]] = {}

    def register(self, rule: BaseCustomRule) -> None:
        """
        Register and validate a custom security rule.

        Raises:
            ValueError: If rule metadata fails validation.
        """
        self._validate_rule(rule)

        rule_id = rule.rule_id
        if rule_id in self._rules_by_id:
            logger.warning("Overwriting existing custom rule: '%s'", rule_id)

        self._rules_by_id[rule_id] = rule

        for ext in rule.file_extensions:
            norm_ext = ext.lower().strip()
            if norm_ext not in self._rules_by_ext:
                self._rules_by_ext[norm_ext] = []
            if rule not in self._rules_by_ext[norm_ext]:
                self._rules_by_ext[norm_ext].append(rule)

    def _validate_rule(self, rule: BaseCustomRule) -> None:
        """Enforce metadata conventions and security constraints on custom rules."""
        if not rule.rule_id or not isinstance(rule.rule_id, str):
            raise ValueError(f"Rule {rule.__class__.__name__} has invalid rule_id: must be non-empty string.")

        if not rule.rule_id.startswith("custom."):
            raise ValueError(f"Rule '{rule.rule_id}' must begin with 'custom.' prefix.")

        if rule.severity not in VALID_SEVERITIES:
            raise ValueError(f"Rule '{rule.rule_id}' has invalid severity '{rule.severity}'.")

        if rule.confidence not in VALID_CONFIDENCES:
            raise ValueError(f"Rule '{rule.rule_id}' has invalid confidence '{rule.confidence}'.")

        if rule.canonical_domain not in VALID_CANONICAL_DOMAINS:
            raise ValueError(
                f"Rule '{rule.rule_id}' has invalid canonical_domain '{rule.canonical_domain}'. "
                f"Must be one of: {sorted(VALID_CANONICAL_DOMAINS)}"
            )

        if not rule.file_extensions or not isinstance(rule.file_extensions, tuple):
            raise ValueError(f"Rule '{rule.rule_id}' file_extensions must be a non-empty tuple of extensions.")

        for ext in rule.file_extensions:
            if not ext.startswith("."):
                raise ValueError(f"Rule '{rule.rule_id}' extension '{ext}' must start with a dot ('.').")

    def get_rule(self, rule_id: str) -> BaseCustomRule | None:
        """Retrieve a registered rule by its rule_id."""
        return self._rules_by_id.get(rule_id)

    def get_rules_for_extension(self, ext: str) -> list[BaseCustomRule]:
        """Retrieve all rules applicable to a specific file extension (e.g., '.py')."""
        return self._rules_by_ext.get(ext.lower().strip(), [])

    def get_all_rules(self) -> list[BaseCustomRule]:
        """Return a list of all registered custom rules."""
        return list(self._rules_by_id.values())

    def clear(self) -> None:
        """Clear all registered rules."""
        self._rules_by_id.clear()
        self._rules_by_ext.clear()

    def evaluate_file(
        self,
        rel_path: str,
        content: str,
    ) -> list[dict[str, Any]]:
        """
        Evaluate applicable custom rules against a single file with fault isolation.

        Args:
            rel_path: Workspace-relative POSIX file path.
            content: Entire text content of the target file.

        Returns:
            list[dict[str, Any]]: Sanitized, redacted raw findings.
        """
        ext = Path(rel_path).suffix.lower()
        rules = self.get_rules_for_extension(ext)
        if not rules:
            return []

        lines = content.splitlines()
        findings: list[dict[str, Any]] = []

        for rule in rules:
            try:
                raw_matches = rule.evaluate(rel_path, content, lines)
                for raw_f in raw_matches:
                    # Apply mandatory in-memory redaction and evidence bounding
                    evidence = raw_f.get("evidence") or ""
                    redacted = BaseScanner.redact_evidence(evidence)
                    bounded = BaseScanner.bound_evidence(redacted, max_chars=1000)

                    finding_dict = dict(raw_f)
                    finding_dict["evidence"] = bounded
                    findings.append(finding_dict)
            except Exception as exc:
                logger.error(
                    "Custom rule '%s' raised an unhandled exception while evaluating '%s': %s",
                    rule.rule_id,
                    rel_path,
                    exc,
                )
                continue

        return findings


# Global registry singleton
default_registry = RuleRegistry()
