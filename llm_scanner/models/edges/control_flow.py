from enum import StrEnum
from typing import Literal

from pydantic import Field

from .base import RelationshipBase


class ControlFlowRelationshipType(StrEnum):
    """Enumerates control-flow relationship kinds."""

    CONTAINS = "CONTAINS"
    NEXT = "NEXT"


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
