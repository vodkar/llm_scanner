from enum import StrEnum
from pathlib import Path
from pydantic import BaseModel, Field

from models.base import NodeID


class VariableScope(StrEnum):
    """Enumeration of variable scopes within Python code."""

    LOCAL = "local"
    GLOBAL = "global"
    PARAMETER = "parameter"
    ATTRIBUTE = "attribute"


class VariableNode(BaseModel):
    """Represents a variable definition or reference."""

    identifier: NodeID = Field(..., description="Unique class identifier")
    name: str = Field(..., description="Variable name")
    # scope: VariableScope = Field(..., description="Scope of the variable")
    type_hint: str = Field(default="", description="Type annotation if provided")
    line_start: int = Field(
        ..., ge=1, description="Starting line number of the function definition"
    )
    line_end: int = Field(
        ..., ge=1, description="Ending line number of the function definition"
    )
    file_path: Path = Field(
        ..., description="Path to the source file containing the variable"
    )
    # is_user_input: bool = Field(
    #     default=False, description="Indicates if value originates from user input"
    # )
    # is_sensitive: bool = Field(
    #     default=False, description="Indicates if value may hold sensitive data"
    # )
