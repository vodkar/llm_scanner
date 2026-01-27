from pathlib import Path

from pydantic import BaseModel

from models.base import StaticAnalyzerIssue


class FlakeIssue(StaticAnalyzerIssue):
    """Single Flake finding.

    Attributes:
        code: flake rule ID (e.g., "DUO105").
        file: Path to the file where the issue was found.
        description: Human-readable description of the issue.
        line_number: Line number where the issue occurs (1-based).
        column_number: Column number where the issue occurs (1-based).
    """

    code: str
    file: Path
    column_number: int


class DlintIssue(FlakeIssue):
    @property
    def id(self) -> int:
        return int(self.code.strip("DUO"))


class DlintReport(BaseModel):
    """Dlint scan results container."""

    issues: list[DlintIssue]
