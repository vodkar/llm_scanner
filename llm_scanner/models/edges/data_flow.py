from enum import StrEnum
from typing import Literal

from pydantic import Field

from .base import RelationshipBase


class DataFlowRelationshipType(StrEnum):
    """Enumerates data-flow relationship kinds."""

    DEFINED_BY = "DEFINED_BY"
    USED_BY = "USED_BY"
    FLOWS_TO = "FLOWS_TO"
    SANITIZED_BY = "SANITIZED_BY"


class DefinitionOperation(StrEnum):
    """Supported operations that introduce a variable definition."""

    ASSIGNMENT = "assignment"
    PARAMETER = "parameter"
    RETURN_VALUE = "return"


class DataFlowDefinedBy(RelationshipBase):
    """Captures how a variable is defined by another variable or call site.

    Attributes:
        type: Relationship type identifier fixed to DEFINED_BY.
        operation: Operation responsible for establishing the definition.
    """

    type: Literal[DataFlowRelationshipType.DEFINED_BY] = Field(
        default=DataFlowRelationshipType.DEFINED_BY,
        description="Relationship type identifier",
    )
    operation: DefinitionOperation = Field(
        ..., description="Operation responsible for producing the value"
    )


class DataFlowFlowsTo(RelationshipBase):
    """Models taint-aware data movement between sources, variables, and sinks.

    Attributes:
        type: Relationship type identifier fixed to FLOWS_TO.
        transformation: Transformation applied to data while flowing.
        is_sanitized: Whether the data has passed through a sanitizer.
        hops: Path length between the source and destination nodes.
        confidence: Confidence score for the detected flow.
    """

    type: Literal[DataFlowRelationshipType.FLOWS_TO] = Field(
        default=DataFlowRelationshipType.FLOWS_TO,
        description="Relationship type identifier",
    )
    # is_sanitized: bool = Field(
    #     default=False,
    #     description="Indicates whether the flow passed through a sanitizer",
    # )


class DataFlowSanitizedBy(RelationshipBase):
    """Links variables to sanitizers that cleanse their data.

    Attributes:
        type: Relationship type identifier fixed to SANITIZED_BY.
        at_line: Line number where sanitization occurs.
    """

    type: Literal[DataFlowRelationshipType.SANITIZED_BY] = Field(
        default=DataFlowRelationshipType.SANITIZED_BY,
        description="Relationship type identifier",
    )
    at_line: int = Field(..., ge=1, description="Line number where sanitization occurs")
