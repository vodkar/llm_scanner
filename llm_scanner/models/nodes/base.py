from enum import StrEnum
from pathlib import Path
from typing import Self

from pydantic import BaseModel, Field, model_validator

from models.base import NodeID


class NodeType(StrEnum):
    """Enumeration of generic node categories."""

    FUNCTION = "Function"
    CLASS = "Class"
    MODULE = "Module"


class BaseCodeNode(BaseModel):
    identifier: NodeID = Field(..., description="Unique identifier")
    file_path: Path = Field(
        ..., description="Path to the source file containing the call"
    )
    line_start: int = Field(..., ge=1, description="Starting line number of the call")
    line_end: int = Field(..., ge=1, description="Ending line number of the call")
    token_count: int = Field(
        default=0, ge=0, description="Approximate token count for LLM budgeting"
    )

    @model_validator(mode="after")
    def validate_line_range(self) -> Self:
        """Ensure line_end is not before line_start."""

        if self.line_end < self.line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        return self
