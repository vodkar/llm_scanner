from pathlib import Path

from pydantic import BaseModel, Field

from models.base import NodeID


class ModuleNode(BaseModel):
    """Represents a Python module or package."""

    identifier: NodeID = Field(..., description="Unique class identifier")
    name: str = Field(..., description="Module name")
    file_path: Path = Field(..., description="Path to the module or package entry file")
