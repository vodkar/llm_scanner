from enum import StrEnum
from typing import Literal

from pydantic import Field

from .base import FindingRelationshipBase


class AnalysisRelationshipType(StrEnum):
    """Enumerates analysis relationships between findings and code artifacts."""

    REPORTS = "REPORTS"
    SUGGESTS_VULNERABILITY = "SUGGESTS_VULNERABILITY"


class StaticAnalysisReports(FindingRelationshipBase):
    """Links a finding to the code artifact it reports on.

    Attributes:
        type: Relationship type identifier fixed to REPORTS.
        reasoning: Explanation provided by the analysis tool.
        examined_nodes: Identifiers of nodes inspected by the analyzer.
    """

    type: Literal[AnalysisRelationshipType.REPORTS] = Field(
        default=AnalysisRelationshipType.REPORTS,
        description="Relationship type identifier",
    )
