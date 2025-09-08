from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel


class IssueSeverity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class BanditIssue(BaseModel):
    cwe: int
    file: Path
    severity: IssueSeverity
    description: str
    line_number: int
    column_number: int
    line_range: list[int]


class BanditReport(BaseModel):
    issues: list[BanditIssue]
