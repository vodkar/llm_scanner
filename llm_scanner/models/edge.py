from enum import StrEnum
from pydantic import BaseModel

class EdgeType(StrEnum):
    CALLS = "CALLS"
    DEFINES = "DEFINES"
    CONTAINS = "CONTAINS"

class Edge(BaseModel):
    src: str
    dst: str
    type: EdgeType