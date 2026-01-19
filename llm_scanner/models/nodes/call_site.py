from pathlib import Path
from pydantic import BaseModel, Field

from models.base import NodeID


class CallNode(BaseModel):
    """Represents a function or method invocation."""

    identifier: NodeID = Field(..., description="Unique call site identifier")
    caller_id: NodeID = Field(
        ..., description="Identifier of the function/method where the call occurs"
    )
    callee_id: NodeID = Field(
        ..., description="Identifier of the function/method being called"
    )
    line_start: int = Field(..., ge=1, description="Starting line number of the call")
    line_end: int = Field(..., ge=1, description="Ending line number of the call")
    file_path: Path = Field(
        ..., description="Path to the source file containing the call"
    )
    # is_external_library: bool = Field(
    #     default=False, description="True if the call targets a third-party library"
    # )
    # library_name: str = Field(
    #     default="", description="Name of the external library if applicable"
    # )
