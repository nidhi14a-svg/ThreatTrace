from typing import Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str
    domain: str
    rule_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    file: str
    line: int | None = None
    evidence: str
    confidence: str
    explanation: str | None = None
    recommendation: str | None = None
    tool: str
    raw_category: str | None = None
