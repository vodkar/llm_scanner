from pydantic import Field

from models.nodes.base import BaseCodeNode


class VariableNode(BaseCodeNode):
    """Represents a variable definition or reference."""

    name: str = Field(..., description="Variable name")
    type_hint: str = Field(default="", description="Type annotation if provided")
    # is_user_input: bool = Field(
    #     default=False, description="Indicates if value originates from user input"
    # )
    # is_sensitive: bool = Field(
    #     default=False, description="Indicates if value may hold sensitive data"
    # )
