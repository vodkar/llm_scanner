from enum import StrEnum
from pathlib import Path
from pydantic import BaseModel, Field, model_validator

from models.base import NodeID


class CodeBlockType(StrEnum):
    """Enumeration of supported code block constructs."""

    IF = "if"
    FOR = "for"
    WHILE = "while"
    TRY = "try"
    WITH = "with"


class FunctionNode(BaseModel):
    """Represents a function or method definition."""

    identifier: NodeID = Field(..., description="Unique function identifier")
    name: str = Field(..., description="Function name")
    # module_name: str = Field(
    #     ..., description="Fully qualified name including module and class"
    # )
    # code: str = Field(..., description="Complete source code of the function")
    # signature: str = Field(
    #     default="", description="Function signature with type hints if available"
    # )
    line_start: int = Field(
        ..., ge=1, description="Starting line number of the function definition"
    )
    line_end: int = Field(
        ..., ge=1, description="Ending line number of the function definition"
    )
    file_path: Path = Field(
        ..., description="Path to the source file containing the function"
    )
    token_count: int = Field(
        default=0, ge=0, description="Approximate token count for LLM budgeting"
    )
    # cyclomatic_complexity: int = Field(
    #     default=0, ge=0, description="Cyclomatic complexity of the function"
    # )
    # num_parameters: int = Field(
    #     default=0, ge=0, description="Number of parameters the function accepts"
    # )
    # has_decorators: bool = Field(
    #     default=False, description="Whether the function has decorators"
    # )

    @model_validator(mode="after")
    def validate_line_range(self) -> "FunctionNode":
        """Ensure line_end is not before line_start."""

        if self.line_end < self.line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        return self


class ClassNode(BaseModel):
    """Represents a class definition."""

    identifier: NodeID = Field(..., description="Unique class identifier")
    name: str = Field(..., description="Class name")
    # qualified_name: str = Field(
    #     ..., description="Fully qualified name including module path"
    # )
    file_path: Path = Field(..., description="File containing the class definition")
    line_start: int = Field(..., ge=1, description="Starting line number")
    line_end: int = Field(..., ge=1, description="Ending line number")
    # bases: list[str] = Field(
    #     default_factory=list, description="Base classes as written in source"
    # )

    @model_validator(mode="after")
    def validate_line_range(self) -> "ClassNode":
        """Ensure the ending line is not before the starting line."""

        if self.line_end < self.line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        return self


class CodeBlockNode(BaseModel):
    """Represents a structured code block such as loops or conditionals."""

    identifier: NodeID = Field(..., description="Unique class identifier")
    type: CodeBlockType = Field(..., description="Type of the code block")
    code: str = Field(..., description="Source code contained within the block")
    line_start: int = Field(..., ge=1, description="Starting line number of the block")
    line_end: int = Field(..., ge=1, description="Ending line number of the block")
    file_path: Path = Field(
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
