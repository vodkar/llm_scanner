from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from models.bandit_report import IssueSeverity
from models.nodes.taint import TaintSinkType, TaintSourceType


class FindingNode(BaseModel):
    identifier: UUID = Field(default_factory=uuid4)
    file: Path
    line_number: int


class BanditFindingNode(FindingNode):
    cwe_id: int
    severity: IssueSeverity


class DlintFindingNode(FindingNode):
    issue_id: int


class PysaFindingNode(FindingNode):
    flow_code: int
    flow_name: str
    sink_type: TaintSinkType
    source_type: TaintSourceType | None = None
