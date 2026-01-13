from pathlib import Path
from pydantic import BaseModel, Field

from models.base import NodeID


class ModuleNode(BaseModel):
    """Represents a Python module or package."""

    identifier: NodeID = Field(..., description="Unique class identifier")
    name: str = Field(..., description="Module name")
    file_path: Path = Field(..., description="Path to the module or package entry file")
    imports: list[str] = Field(
        default_factory=list, description="Imported modules and symbols"
    )
    exports: list[str] = Field(
        default_factory=list, description="Publicly exported symbols"
    )
    is_entry_point: bool = Field(
        default=False, description="Indicates if the module acts as an entry point"
    )
