from typing import Literal

from pydantic import BaseModel


class ScanStatus(BaseModel):
    scan_id: str
    status: Literal["pending", "processing", "completed", "failed"]
