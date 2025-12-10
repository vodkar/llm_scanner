from pydantic import BaseModel, Field


class CallSiteNode(BaseModel):
    """Represents a function or method invocation."""

    function_name: str = Field(..., description="Name of the called function or method")
    qualified_name: str = Field(
        default="", description="Fully qualified name if resolvable"
    )
    arguments: list[str] = Field(
        default_factory=list, description="Argument expressions passed to the call"
    )
    line_number: int = Field(..., ge=1, description="Line number where the call occurs")
    file_path: str = Field(
        ..., description="Path to the source file containing the call"
    )
    is_external_library: bool = Field(
        default=False, description="True if the call targets a third-party library"
    )
    library_name: str = Field(
        default="", description="Name of the external library if applicable"
    )
