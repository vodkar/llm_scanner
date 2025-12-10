from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel, Field


class FindingTool(StrEnum):
    """Supported static analysis tools."""

    BANDIT = "bandit"
    PYSA = "pysa"
    SEMGREP = "semgrep"


class FindingSeverity(StrEnum):
    """Severity levels for findings."""

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


class FindingNode(BaseModel):
    """Represents a static analysis finding from security tools."""

    tool: FindingTool = Field(..., description="Originating tool of the finding")
    rule_id: str = Field(..., description="Identifier of the triggered rule")
    severity: FindingSeverity = Field(..., description="Reported severity level")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score from the tool"
    )
    message: str = Field(..., description="Human-readable description of the issue")
    line_number: int = Field(..., ge=1, description="Line where the issue occurs")
    file_path: str = Field(..., description="Path to the file with the issue")
    cwe_id: str = Field(default="", description="Associated CWE identifier if any")
    fix_suggestion: str = Field(
        default="", description="Suggested remediation for the finding"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Timestamp when analysis ran"
    )
