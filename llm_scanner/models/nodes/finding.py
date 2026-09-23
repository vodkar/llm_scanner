from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from models.bandit_report import IssueSeverity


class FindingNode(BaseModel):
    identifier: UUID = Field(default_factory=uuid4)
    file: Path
    line_number: int
    line_end: int | None = Field(
        default=None,
        description="Last line of the reported range; None for single-line findings",
    )
    column_number: int = Field(default=0, ge=0, description="Reported column offset")
    rule_id: str = Field(default="", description="Analyzer rule id, e.g. B602 or DUO102")
    reason: str = Field(default="", description="Analyzer message")


class BanditFindingNode(FindingNode):
    cwe_id: int
    severity: IssueSeverity


class DlintFindingNode(FindingNode):
    issue_id: int


class SemgrepFindingNode(FindingNode):
    cwe_id: int | None = None
    severity: IssueSeverity
