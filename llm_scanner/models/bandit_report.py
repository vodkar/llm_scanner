from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from models.base import StaticAnalyzerIssue, StaticAnalyzerReport


class IssueSeverity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class BanditIssue(StaticAnalyzerIssue):
    cwe: int
    severity: IssueSeverity
    line_number: int
    column_number: int
    line_range: list[int]
    # byte: int
