from pydantic import BaseModel, Field

from models.base import NodeID


class RelationshipBase(BaseModel):
    """Base relationship connecting two graph nodes.

    Attributes:
        src: Source node identifier in the graph.
        dst: Destination node identifier in the graph.
    """

    src: NodeID = Field(..., description="Source node identifier")
    dst: NodeID = Field(..., description="Destination node identifier")
