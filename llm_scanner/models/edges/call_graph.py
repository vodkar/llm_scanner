from enum import StrEnum
from typing import Literal

from pydantic import Field

from .base import RelationshipBase


class CallGraphRelationshipType(StrEnum):
    """Enumerates call-graph relationship kinds."""

    CALLS = "CALLS"
    CALLED_BY = "CALLED_BY"


class CallGraphCalls(RelationshipBase):
    """Represents a call site invoking a function.

    Attributes:
        type: Relationship type identifier fixed to CALLS.
        is_direct: Whether the call is direct (vs. dynamic/indirect).
        call_depth: Depth of the call within the call chain.
    """

    type: Literal[CallGraphRelationshipType.CALLS] = Field(
        default=CallGraphRelationshipType.CALLS,
        description="Relationship type identifier",
    )
    is_direct: bool = Field(..., description="True for direct calls; False otherwise")
    call_depth: int = Field(
        ..., ge=0, description="Depth of the call within the call chain"
    )


class CallGraphCalledBy(RelationshipBase):
    """Represents function-to-function call relationships.

    Attributes:
        type: Relationship type identifier fixed to CALLED_BY.
        call_count: Number of times the call occurs if known.
        is_entry_point_path: Whether the edge lies on a path from main/entry point.
    """

    type: Literal[CallGraphRelationshipType.CALLED_BY] = Field(
        default=CallGraphRelationshipType.CALLED_BY,
        description="Relationship type identifier",
    )
    call_count: int | None = Field(
        default=None,
        ge=0,
        description="Number of observed calls when profiling data is available",
    )
    is_entry_point_path: bool = Field(
        default=False,
        description="True if the edge lies on a path from the application entry point",
    )
