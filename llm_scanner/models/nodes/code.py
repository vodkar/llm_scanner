from pathlib import Path
from pydantic import BaseModel, Field, model_validator

from models.base import NodeID
from models.nodes.base import BaseCodeNode


class FunctionNode(BaseCodeNode):
    """Represents a function or method definition."""

    name: str = Field(..., description="Function name")
    # module_name: str = Field(
    #     ..., description="Fully qualified name including module and class"
    # )
    # code: str = Field(..., description="Complete source code of the function")
    # signature: str = Field(
    #     default="", description="Function signature with type hints if available"
    # )
    # cyclomatic_complexity: int = Field(
    #     default=0, ge=0, description="Cyclomatic complexity of the function"
    # )
    # num_parameters: int = Field(
    #     default=0, ge=0, description="Number of parameters the function accepts"
    # )
    # has_decorators: bool = Field(
    #     default=False, description="Whether the function has decorators"
    # )


class ClassNode(BaseCodeNode):
    """Represents a class definition."""

    name: str = Field(..., description="Class name")
    # qualified_name: str = Field(
    #     ..., description="Fully qualified name including module path"
    # )
    # bases: list[str] = Field(
    #     default_factory=list, description="Base classes as written in source"
    # )


class CodeBlockNode(BaseCodeNode):
    """Represents a top-level code block outside classes or functions."""
