from enum import StrEnum
from typing import Literal

from pydantic import Field

from .base import RelationshipBase


class ControlFlowRelationshipType(StrEnum):
    """Enumerates control-flow relationship kinds."""

    CONTAINS = "CONTAINS"
    NEXT = "NEXT"


class BranchType(StrEnum):
    """Branch edge variants for code block transitions."""

    SEQUENTIAL = "sequential"
    IF_TRUE = "if_true"
    IF_FALSE = "if_false"
    LOOP = "loop"


class ControlFlowContains(RelationshipBase):
    """Maps functions to the code blocks they contain.

    Attributes:
        type: Relationship type identifier fixed to CONTAINS.
        position: Order of the code block within the function body (0-indexed).
    """

    type: Literal[ControlFlowRelationshipType.CONTAINS] = Field(
        default=ControlFlowRelationshipType.CONTAINS,
        description="Relationship type identifier",
    )
    position: int = Field(..., ge=0, description="Order of the code block within the function")


class ControlFlowNext(RelationshipBase):
    """Connects sequential or branching code blocks within a function.

    Attributes:
        type: Relationship type identifier fixed to NEXT.
        branch_type: Flow category connecting the two code blocks.
    """

    type: Literal[ControlFlowRelationshipType.NEXT] = Field(
        default=ControlFlowRelationshipType.NEXT,
        description="Relationship type identifier",
    )
    branch_type: BranchType = Field(..., description="Flow category between code blocks")
