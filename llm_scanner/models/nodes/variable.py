from pathlib import Path

from pydantic import BaseModel, Field

from models.base import NodeID


class VariableNode(BaseModel):
    """Represents a variable definition or reference."""

    identifier: NodeID = Field(..., description="Unique class identifier")
    name: str = Field(..., description="Variable name")
    type_hint: str = Field(default="", description="Type annotation if provided")
    line_start: int = Field(
        ..., ge=1, description="Starting line number of the function definition"
    )
    line_end: int = Field(..., ge=1, description="Ending line number of the function definition")
    file_path: Path = Field(..., description="Path to the source file containing the variable")
    # is_user_input: bool = Field(
    #     default=False, description="Indicates if value originates from user input"
    # )
    # is_sensitive: bool = Field(
    #     default=False, description="Indicates if value may hold sensitive data"
    # )
