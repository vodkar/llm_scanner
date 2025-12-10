from enum import StrEnum
from pydantic import BaseModel, Field, model_validator


class CodeBlockType(StrEnum):
    """Enumeration of supported code block constructs."""

    IF = "if"
    FOR = "for"
    WHILE = "while"
    TRY = "try"
    WITH = "with"


class FunctionNode(BaseModel):
    """Represents a function or method definition."""

    name: str = Field(..., description="Function name")
    qualified_name: str = Field(
        ..., description="Fully qualified name including module and class"
    )
    code: str = Field(..., description="Complete source code of the function")
    signature: str = Field(
        default="", description="Function signature with type hints if available"
    )
    docstring: str = Field(default="", description="Docstring content if present")
    line_start: int = Field(
        ..., ge=1, description="Starting line number of the function definition"
    )
    line_end: int = Field(
        ..., ge=1, description="Ending line number of the function definition"
    )
    file_path: str = Field(
        ..., description="Path to the source file containing the function"
    )
    token_count: int = Field(
        default=0, ge=0, description="Approximate token count for LLM budgeting"
    )
    cyclomatic_complexity: int = Field(
        default=0, ge=0, description="Cyclomatic complexity of the function"
    )
    num_parameters: int = Field(
        default=0, ge=0, description="Number of parameters the function accepts"
    )
    has_decorators: bool = Field(
        default=False, description="Whether the function has decorators"
    )

    @model_validator(mode="after")
    def validate_line_range(self) -> "FunctionNode":
        """Ensure line_end is not before line_start."""

        if self.line_end < self.line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        return self


class CodeBlockNode(BaseModel):
    """Represents a structured code block such as loops or conditionals."""

    type: CodeBlockType = Field(..., description="Type of the code block")
    code: str = Field(..., description="Source code contained within the block")
    line_start: int = Field(..., ge=1, description="Starting line number of the block")
    line_end: int = Field(..., ge=1, description="Ending line number of the block")
    file_path: str = Field(
        ..., description="Path to the source file containing the block"
    )
    nesting_level: int = Field(
        default=0, ge=0, description="Depth of nesting for the block"
    )
    token_count: int = Field(
        default=0, ge=0, description="Approximate token count for the block"
    )

    @model_validator(mode="after")
    def validate_line_range(self) -> "CodeBlockNode":
        """Ensure line_end is not before line_start."""

        if self.line_end < self.line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        return self
