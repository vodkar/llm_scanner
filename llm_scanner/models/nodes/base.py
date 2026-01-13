from enum import StrEnum
from pydantic import BaseModel, Field, field_serializer


class NodeType(StrEnum):
    """Enumeration of generic node categories."""

    FUNCTION = "Function"
    CLASS = "Class"
    MODULE = "Module"


class DeprecatedNode(BaseModel):
    """Represents a generic code graph node with derived info sets."""

    id: str
    type: NodeType
    name: str
    qualname: str
    file: str
    lineno: int
    end_lineno: int
    code: str
    imports: set[str] = Field(default_factory=set)
    globals: set[str] = Field(default_factory=set)
    locals: set[str] = Field(default_factory=set)

    @field_serializer("imports", "globals", "locals")
    def sort_derived_info(self, value: set[str]) -> list[str]:
        """Serialize derived sets as sorted lists for deterministic output."""

        return sorted(value)
