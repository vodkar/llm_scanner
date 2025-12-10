from pydantic import BaseModel, Field


class ModuleNode(BaseModel):
    """Represents a Python module or package."""

    name: str = Field(..., description="Module name")
    file_path: str = Field(..., description="Path to the module or package entry file")
    imports: list[str] = Field(
        default_factory=list, description="Imported modules and symbols"
    )
    exports: list[str] = Field(
        default_factory=list, description="Publicly exported symbols"
    )
    is_entry_point: bool = Field(
        default=False, description="Indicates if the module acts as an entry point"
    )
