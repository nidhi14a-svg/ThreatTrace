"""
Prompt templates and formatting utilities for sanitized AI security analysis.

Enforces the AI context boundary: external LLMs receive only pre-sanitized,
bounded finding metadata, never raw source files or repository trees.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.ai.ai_service import AIFindingContext

SYSTEM_PROMPT: str = (
    "You are an expert Application Security and Code Audit Assistant working on Thread Trace. "
    "Your objective is to provide a concise, technical explanation of a detected security vulnerability "
    "and actionable, code-level remediation steps. "
    "You must rely strictly on the provided sanitized finding metadata. "
    "Do not hallucinate files or context outside the provided finding. "
    "Format your output as structured text containing an Explanation section and a Recommendation section."
)


def format_finding_prompt(context: "AIFindingContext") -> str:
    """
    Format sanitized finding context into a structured, bounded prompt for the AI model.

    Args:
        context: Validated AIFindingContext containing strictly bounded finding metadata.

    Returns:
        str: Structured prompt string containing only sanitized finding attributes.
    """
    line_str = f"Line {context.line}" if context.line is not None else "Manifest / File-level"
    return (
        f"Vulnerability Title: {context.title}\n"
        f"Security Domain: {context.domain}\n"
        f"Scanner Rule ID: {context.rule_id}\n"
        f"Severity: {context.severity.upper()}\n"
        f"Location: {context.file} ({line_str})\n"
        f"Confidence: {context.confidence.upper()}\n\n"
        f"Code Context / Evidence:\n"
        f"```\n{context.evidence}\n```\n\n"
        f"Instructions:\n"
        f"1. Explain the underlying security risk and potential exploit scenario in 2-3 sentences.\n"
        f"2. Provide concrete, actionable remediation guidance with code examples where applicable."
    )
