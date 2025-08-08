# ---------------- Models -----------------

from enum import StrEnum
from pydantic import BaseModel, Field, field_serializer



class NodeType(StrEnum):
    FUNCTION = "Function"
    CLASS = "Class"
    MODULE = "Module"

class Node(BaseModel):
    id: str
    type: NodeType
    name: str
    qualname: str
    file: str
    lineno: int
    end_lineno: int
    code: str
    # derived info
    imports: set[str] = Field(default_factory=set)
    globals: set[str] = Field(default_factory=set)
    locals: set[str] = Field(default_factory=set)

    @field_serializer("imports", "globals", "locals")
    def sort_derived_info(self, v: set[str]) -> list[str]:
        return sorted(v)