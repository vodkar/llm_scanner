from pathlib import Path
from typing import NamedTuple

from pydantic import BaseModel, Field

from models.base import NodeID
from models.nodes.finding import FindingNode


class CodeContextNode(BaseModel):
    """Represents a code node included in LLM context."""

    node_id: NodeID = Field(..., description="Code node identifier")
    node_kind: str | None = Field(default=None, description="Type of code node")
    name: str | None = Field(default=None, description="Optional node name")
    file_path: Path = Field(..., description="Relative path to the source file")
    line_start: int = Field(..., description="Start line for the node")
    line_end: int = Field(..., description="End line for the node")
    depth: int = Field(..., ge=0, description="Traversal depth from the finding node")
    repeats: int = Field(
        default=0, ge=0, description="Number of times this node is repeated in context"
    )
    findings: list[FindingNode] = Field(
        default_factory=list[FindingNode], description="Findings associated with this node"
    )


class Context(BaseModel):
    """LLM context assembled for a single finding."""

    description: str = Field(..., description="Short linter description")
    # nodes: list[CodeContextNode] = Field(
    #     default_factory=list[CodeContextNode], description="Context nodes"
    # )
    context_text: str = Field(default="", description="Rendered LLM context")
    token_count: int = Field(default=0, ge=0, description="Estimated token count")


class ContextAssembly(BaseModel):
    """Context bundle for all findings in a project."""

    contexts: list[Context] = Field(default_factory=list[Context])


class FileSpans(NamedTuple):
    file_path: Path
    line_spans: list[tuple[int, int]]
