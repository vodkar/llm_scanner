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
    """

    type: Literal[CallGraphRelationshipType.CALLS] = Field(
        default=CallGraphRelationshipType.CALLS,
        description="Relationship type identifier",
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
