from pathlib import Path
from pydantic import BaseModel, Field

from models.base import NodeID
from models.nodes.base import BaseCodeNode


class CallNode(BaseCodeNode):
    """Represents a function or method invocation."""

    caller_id: NodeID = Field(
        ..., description="Identifier of the function/method where the call occurs"
    )
    callee_id: NodeID = Field(
        ..., description="Identifier of the function/method being called"
    )
    # is_external_library: bool = Field(
    #     default=False, description="True if the call targets a third-party library"
    # )
    # library_name: str = Field(
    #     default="", description="Name of the external library if applicable"
    # )
