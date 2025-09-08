from pathlib import Path

from pydantic import BaseModel


class DlintIssue(BaseModel):
    """Single Dlint finding.

    Attributes:
        code: Dlint rule ID (e.g., "DUO105").
        file: Path to the file where the issue was found.
        description: Human-readable description of the issue.
        line_number: Line number where the issue occurs (1-based).
        column_number: Column number where the issue occurs (1-based).
    """

    code: str
    file: Path
    description: str
    line_number: int
    column_number: int


class DlintReport(BaseModel):
    """Dlint scan results container."""

    issues: list[DlintIssue]
