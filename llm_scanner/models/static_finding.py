"""Static-analysis finding resolved to a location inside a rendered snippet."""

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from models.bandit_report import IssueSeverity


class AnalyzerTool(StrEnum):
    """Static analyzers whose findings can be attached to a snippet."""

    BANDIT = "bandit"
    DLINT = "dlint"
    SEMGREP = "semgrep"


class StaticFinding(BaseModel):
    """Analyzer report located both in the repository and in the rendered snippet."""

    tool: AnalyzerTool = Field(..., description="Analyzer that produced the report")
    rule_id: str = Field(
        ..., description="Analyzer rule id, e.g. B602, DUO102 or a Semgrep check id"
    )
    cwe_id: int | None = Field(default=None, description="CWE id (Bandit/Semgrep)")
    severity: IssueSeverity | None = Field(default=None, description="Severity (Bandit/Semgrep)")
    message: str = Field(..., description="Analyzer message")
    file_path: Path = Field(..., description="Repo-relative file path")
    repo_line: int = Field(..., ge=1, description="1-based line in the repository file")
    snippet_line: int = Field(..., ge=1, description="1-based line in the rendered snippet")
    is_root: bool = Field(..., description="True if the line lies inside a root node")
