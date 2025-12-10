from enum import StrEnum
from pydantic import BaseModel, Field


class VariableScope(StrEnum):
    """Enumeration of variable scopes within Python code."""

    LOCAL = "local"
    GLOBAL = "global"
    PARAMETER = "parameter"
    ATTRIBUTE = "attribute"


class VariableNode(BaseModel):
    """Represents a variable definition or reference."""

    name: str = Field(..., description="Variable name")
    scope: VariableScope = Field(..., description="Scope of the variable")
    type_hint: str = Field(default="", description="Type annotation if provided")
    line_number: int = Field(
        ..., ge=1, description="Line number where the variable appears"
    )
    file_path: str = Field(
        ..., description="Path to the source file containing the variable"
    )
    is_user_input: bool = Field(
        default=False, description="Indicates if value originates from user input"
    )
    is_sensitive: bool = Field(
        default=False, description="Indicates if value may hold sensitive data"
    )
