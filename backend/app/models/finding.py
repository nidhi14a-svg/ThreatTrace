from datetime import datetime, timezone
from typing import Literal

FindingSeverity = Literal["critical", "high", "medium", "low"]


class FindingRecord:
    """Lightweight persistence placeholder; MongoDB integration belongs in the database module."""

    def __init__(self, finding_id: str, data: dict) -> None:
        self.finding_id = finding_id
        self.data = data
        self.created_at = datetime.now(timezone.utc)
