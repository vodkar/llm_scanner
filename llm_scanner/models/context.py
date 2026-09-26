from pathlib import Path
from typing import NamedTuple, Self

from pydantic import BaseModel, Field, model_validator

from models.base import NodeID
from models.static_finding import StaticFinding


class CodeContextNode(BaseModel):
    """Represents a code node included in LLM context."""

    identifier: NodeID = Field(..., description="Code node identifier")
    node_kind: str | None = Field(default=None, description="Type of code node")
    name: str | None = Field(default=None, description="Optional node name")
    file_path: Path = Field(..., description="Relative path to the source file")
    line_start: int = Field(..., description="Start line for the node")
    line_end: int = Field(..., description="End line for the node")
    depth: int = Field(..., ge=0, description="Traversal depth from the finding node")
    repeats: int = Field(
        default=0, ge=0, description="Number of times this node is repeated in context"
    )
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Relevance score for ranking in context assembly",
    )
    finding_evidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Finding-derived evidence score for ranking",
    )
    security_path_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Security path score for ranking",
    )
    context_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Context-only relevance score for ranking",
    )
    taint_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Backward DataFlow taint distance score from root nodes",
    )
    edge_depths: dict[str, int] | None = Field(
        default=None,
        description=(
            "Per-edge-type minimum depth at which this node is reachable. "
            "Populated only by strategies that request edge-type-aware traversal."
        ),
    )


class SnippetSegment(BaseModel):
    """Maps a run of consecutive snippet lines from one file back to repo lines.

    ``repo_lines[i]`` is the repository line rendered at snippet line
    ``snippet_line_start + i``. Repo lines may be non-contiguous because blank
    and comment-only lines are dropped during rendering.
    """

    file_path: Path = Field(..., description="Repo-relative source file")
    snippet_line_start: int = Field(..., ge=1, description="1-based first snippet line")
    snippet_line_end: int = Field(..., ge=1, description="1-based last snippet line (inclusive)")
    repo_lines: tuple[int, ...] = Field(..., description="Repo line for each snippet line")

    @model_validator(mode="after")
    def _check_lengths(self) -> Self:
        expected = self.snippet_line_end - self.snippet_line_start + 1
        if len(self.repo_lines) != expected:
            raise ValueError(f"repo_lines has {len(self.repo_lines)} entries, expected {expected}")
        return self


class Context(BaseModel):
    """LLM context assembled for a single finding."""

    description: str = Field(..., description="Short linter description")
    # nodes: list[CodeContextNode] = Field(
    #     default_factory=list[CodeContextNode], description="Context nodes"
    # )
    context_text: str = Field(default="", description="Rendered LLM context")
    token_count: int = Field(default=0, ge=0, description="Estimated token count")
    source_map: list[SnippetSegment] = Field(
        default_factory=list, description="Snippet line → repo location mapping"
    )
    static_findings: list[StaticFinding] = Field(
        default_factory=list, description="Analyzer findings located in the snippet"
    )


class FileSpans(NamedTuple):
    file_path: Path
    line_spans: list[tuple[int, int]]
