from enum import StrEnum
from typing import Literal

from pydantic import Field

from .base import RelationshipBase


class AnalysisRelationshipType(StrEnum):
    """Enumerates analysis relationships between findings and code artifacts."""

    REPORTS = "REPORTS"
    SUGGESTS_VULNERABILITY = "SUGGESTS_VULNERABILITY"
    CONFLICTS_WITH = "CONFLICTS_WITH"


class AnalysisReports(RelationshipBase):
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
    reasoning: str = Field(..., description="Why the analyzer raised the finding")
    examined_nodes: list[str] = Field(
        default_factory=list,
        description="Graph node identifiers reviewed by the analyzer",
    )


class AnalysisSuggestsVulnerability(RelationshipBase):
    """Connects a finding to a potential vulnerability sink.

    Attributes:
        type: Relationship type identifier fixed to SUGGESTS_VULNERABILITY.
        probability: Ensemble or model score representing likelihood of vulnerability.
    """

    type: Literal[AnalysisRelationshipType.SUGGESTS_VULNERABILITY] = Field(
        default=AnalysisRelationshipType.SUGGESTS_VULNERABILITY,
        description="Relationship type identifier",
    )
    probability: float = Field(
        ..., ge=0.0, le=1.0, description="Probability score for the suggested issue"
    )


class AnalysisConflictsWith(RelationshipBase):
    """Represents conflicts between findings from different analyses.

    Attributes:
        type: Relationship type identifier fixed to CONFLICTS_WITH.
        conflict_type: Nature of the disagreement between findings.
    """

    type: Literal[AnalysisRelationshipType.CONFLICTS_WITH] = Field(
        default=AnalysisRelationshipType.CONFLICTS_WITH,
        description="Relationship type identifier",
    )
    conflict_type: str = Field(
        ..., description="Description of the conflict between findings"
    )
