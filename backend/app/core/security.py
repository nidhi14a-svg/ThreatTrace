"""
Core security utilities and secret redaction engine for Thread Trace.

Provides centralized in-memory credential redaction, log sanitization,
evidence bounding, and unmasked secret verification across the platform.
"""

import re
from typing import ClassVar


class RedactionEngine:
    """Centralized regex-based secret redaction engine."""

    # AWS Access Key ID
    RE_AWS_KEY: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(AKIA[0-9A-Z]{16})\b"
    )

    # GitHub Personal Access Tokens
    RE_GITHUB_PAT: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(gh[pousr]_[0-9a-zA-Z]{36})\b"
    )

    # Private Cryptographic Keys
    RE_PRIVATE_KEY: ClassVar[re.Pattern[str]] = re.compile(
        r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"
    )

    # Slack Webhook URLs
    RE_SLACK_WEBHOOK: ClassVar[re.Pattern[str]] = re.compile(
        r"https://hooks\.slack\.com/services/[A-Za-z0-9+/_-]+"
    )

    # Slack Tokens
    RE_SLACK_TOKEN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(xox[baprs]-[0-9a-zA-Z\-]{10,})\b"
    )

    # Stripe Live API Keys
    RE_STRIPE_KEY: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(sk_live_[0-9a-zA-Z]{24,})\b"
    )

    # Bearer Tokens
    RE_BEARER_TOKEN: ClassVar[re.Pattern[str]] = re.compile(
        r"(Bearer\s+)[a-zA-Z0-9_\-\.]{20,}",
        flags=re.IGNORECASE,
    )

    # Database Connection Strings with Passwords
    RE_DB_CONN: ClassVar[re.Pattern[str]] = re.compile(
        r"""((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:]+:)([^@\s'"]+)(@[a-zA-Z0-9_\-\.]+)""",
        flags=re.IGNORECASE,
    )

    @classmethod
    def redact(cls, text: str) -> str:
        """
        Redact all detected sensitive tokens, keys, and credentials from text.

        Args:
            text: Input string (e.g. source snippet, log message, error trace).

        Returns:
            str: Masked string safe for storage, logging, and external transmission.
        """
        if not text:
            return ""

        redacted = text

        # 1. Private keys
        redacted = cls.RE_PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", redacted)

        # 2. Database connection strings (mask password)
        redacted = cls.RE_DB_CONN.sub(r"\g<1>********\g<3>", redacted)

        # 3. AWS Access Keys
        redacted = cls.RE_AWS_KEY.sub("AKIA****************", redacted)

        # 4. GitHub Tokens
        redacted = cls.RE_GITHUB_PAT.sub("[REDACTED_GITHUB_TOKEN]", redacted)

        # 5. Slack Webhooks & Tokens
        redacted = cls.RE_SLACK_WEBHOOK.sub("https://hooks.slack.com/services/[REDACTED]", redacted)
        redacted = cls.RE_SLACK_TOKEN.sub("[REDACTED_SLACK_TOKEN]", redacted)

        # 6. Stripe Keys
        redacted = cls.RE_STRIPE_KEY.sub("[REDACTED_STRIPE_KEY]", redacted)

        # 7. Bearer Tokens
        redacted = cls.RE_BEARER_TOKEN.sub(r"\1[REDACTED_BEARER_TOKEN]", redacted)

        return redacted

    @classmethod
    def contains_unmasked_secret(cls, text: str) -> bool:
        """
        Check whether text contains any identifiable unmasked credentials.

        Returns:
            bool: True if an unmasked secret is found, False otherwise.
        """
        if not text:
            return False

        if cls.RE_AWS_KEY.search(text):
            return True
        if cls.RE_GITHUB_PAT.search(text):
            return True
        if cls.RE_PRIVATE_KEY.search(text):
            return True
        if cls.RE_STRIPE_KEY.search(text):
            return True
        if cls.RE_SLACK_TOKEN.search(text):
            return True

        return False


def redact_secrets(text: str) -> str:
    """Convenience helper to redact secrets from any string."""
    return RedactionEngine.redact(text)


def contains_unmasked_secret(text: str) -> bool:
    """Convenience helper to check for unmasked secrets."""
    return RedactionEngine.contains_unmasked_secret(text)


def sanitize_log(msg: str) -> str:
    """Sanitize log messages before writing to log handlers."""
    return RedactionEngine.redact(msg)


def bound_evidence(evidence: str, max_chars: int = 1000) -> str:
    """Bound evidence string length to max_chars with trailing ellipsis."""
    if not evidence:
        return ""
    if len(evidence) <= max_chars:
        return evidence
    return evidence[: max_chars - 3] + "..."
