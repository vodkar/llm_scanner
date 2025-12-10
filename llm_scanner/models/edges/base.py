from pydantic import BaseModel, Field


class RelationshipBase(BaseModel):
    """Base relationship connecting two graph nodes.

    Attributes:
        src: Source node identifier in the graph.
        dst: Destination node identifier in the graph.
    """

    src: str = Field(..., description="Source node identifier")
    dst: str = Field(..., description="Destination node identifier")
