from pathlib import Path

from pydantic import BaseModel, Field


class CodeContextNode(BaseModel):
    """Represents a code node included in LLM context."""

    node_id: str = Field(..., description="Code node identifier")
    node_kind: str | None = Field(default=None, description="Type of code node")
    name: str | None = Field(default=None, description="Optional node name")
    file_path: Path = Field(..., description="Relative path to the source file")
    line_start: int | None = Field(default=None, description="Start line for the node")
    line_end: int | None = Field(default=None, description="End line for the node")
    depth: int = Field(..., ge=0, description="Traversal depth from the finding node")
    snippet: str = Field(default="", description="Extracted code snippet")


class FindingContext(BaseModel):
    """LLM context assembled for a single finding."""

    finding_id: str = Field(..., description="Finding identifier")
    finding_type: str = Field(..., description="Analyzer label for the finding")
    file: Path = Field(..., description="Relative path to the finding file")
    line_number: int = Field(..., ge=1, description="Line number where the finding occurs")
    description: str = Field(..., description="Short linter description")
    nodes: list[CodeContextNode] = Field(default_factory=list, description="Context nodes")
    context_text: str = Field(default="", description="Rendered LLM context")
    token_count: int = Field(default=0, ge=0, description="Estimated token count")


class ContextAssembly(BaseModel):
    """Context bundle for all findings in a project."""

    findings: list[FindingContext] = Field(default_factory=list)
