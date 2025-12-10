from enum import StrEnum
from pydantic import BaseModel, Field


class EdgeType(StrEnum):
    """Edge categories for legacy code property graph relationships."""

    CALLS = "CALLS"
    DEFINES = "DEFINES"
    CONTAINS = "CONTAINS"


class Edge(BaseModel):
    """Basic edge connecting two nodes in the legacy graph."""

    src: str = Field(..., description="Source node identifier")
    dst: str = Field(..., description="Destination node identifier")
    type: EdgeType = Field(..., description="Edge category")
