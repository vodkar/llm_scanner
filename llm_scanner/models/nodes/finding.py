from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from models.bandit_report import IssueSeverity


class FindingNode(BaseModel):
    identifier: UUID = Field(default=uuid4())
    file: Path
    line_number: int


class BanditFindingNode(FindingNode):
    cwe_id: int
    severity: IssueSeverity


class DlintFindingNode(FindingNode):
    issue_id: int
