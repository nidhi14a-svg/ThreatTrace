from typing import Any

from pydantic import BaseModel


class Report(BaseModel):
    scan_id: str
    report: Any | None = None
