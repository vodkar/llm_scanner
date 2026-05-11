import logging
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from models.base import NodeID
from models.context import CodeContextNode, Context, FileSpans
from repositories.context import ContextRepository
from services.context_assembler.ranking import (
    ContextNodeRankingStrategy,
)

TokenEstimator = Callable[[str], int]
_LOGGER = logging.getLogger(__name__)


class ContextAssemblerService(BaseModel):
    """Assemble LLM context for vulnerability findings."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path
    context_repository: ContextRepository
    max_call_depth: int
    token_budget: int
    snippet_cache_max_entries: int = 10000
    token_estimator: TokenEstimator | None = None
    ranking_strategy: ContextNodeRankingStrategy

    def model_post_init(self, __context: object) -> None:
        """Initialize default ranking strategy when one is not injected."""

        del __context

    @staticmethod
    def _validate_file_spans(files_spans: list[FileSpans]) -> None:
        """Validate file span inputs before querying Neo4j."""

        for file_span in files_spans:
            if any(start < 1 for start, _ in file_span.line_spans):
                raise ValueError("start_line must be >= 1")
            if any(end < start for start, end in file_span.line_spans):
                raise ValueError("end_line must be >= start_line")

    def fetch_root_ids_for_spans(self, files_spans: list[FileSpans]) -> list[str]:
        """Return unique root node IDs overlapping the supplied file spans."""

        self._validate_file_spans(files_spans)

        spans_nodes = self.context_repository.fetch_code_nodes_by_file_spans(
            [
                {
                    "file_path": str(file_span.file_path),
                    "start_line": line_span[0],
                    "end_line": line_span[1],
                }
                for file_span in files_spans
                for line_span in file_span.line_spans
            ]
        )
        _LOGGER.info("Found %d context nodes overlapping file spans", len(spans_nodes))

        return sorted({str(node.identifier) for node in spans_nodes})

    def fetch_context_nodes_for_root_ids(
        self,
        root_ids: list[str],
        *,
        requires_edge_paths: bool | None = None,
    ) -> list[CodeContextNode]:
        """Fetch context neighborhood for the supplied root node IDs."""

        if not root_ids:
            return []

        if requires_edge_paths is None:
            requires_edge_paths = getattr(self.ranking_strategy, "requires_edge_paths", False)

        if requires_edge_paths:
            context_nodes = self.context_repository.fetch_code_neighborhood_with_edge_paths(
                root_ids,
                self.max_call_depth,
            )
        else:
            context_nodes = self.context_repository.fetch_code_neighborhood_batch(
                root_ids,
                self.max_call_depth,
            )
        _LOGGER.info("Fetched neighborhood for %d context nodes", len(context_nodes))
        return context_nodes

    def fetch_taint_scores(self, root_ids: list[str]) -> dict[NodeID, float]:
        """Fetch backward-taint scores for the supplied root node IDs."""

        if not root_ids:
            return {}
        return self.context_repository.fetch_taint_sources(root_ids)

    @staticmethod
    def apply_taint_scores(
        nodes: list[CodeContextNode],
        taint_scores: dict[NodeID, float],
    ) -> list[CodeContextNode]:
        """Return context nodes with taint scores applied."""

        if not taint_scores:
            return nodes
        return [
            node.model_copy(update={"taint_score": taint_scores[node.identifier]})
            if node.identifier in taint_scores
            else node
            for node in nodes
        ]

    def assemble_from_nodes(self, repo_path: Path, nodes: list[CodeContextNode]) -> Context:
        """Rank and render already-fetched context nodes into final text."""

        cloned_nodes: list[CodeContextNode] = [node.model_copy(deep=True) for node in nodes]
        context_text, token_count = self._render_context(repo_path, cloned_nodes)

        return Context(
            description="Finding from spans query",
            context_text=context_text,
            token_count=token_count,
        )

    def assemble_for_spans(self, repo_path: Path, files_spans: list[FileSpans]) -> Context:
        """Assemble context for findings overlapping specific file and line spans."""

        _LOGGER.info(
            "Assembling context for %d file spans in repository: %s",
            len(files_spans),
            repo_path,
        )

        root_ids = self.fetch_root_ids_for_spans(files_spans)
        context_nodes = self.fetch_context_nodes_for_root_ids(root_ids)

        taint_scores: dict[NodeID, float] = {}
        if getattr(self.ranking_strategy, "requires_taint_scores", True):
            taint_scores = self.fetch_taint_scores(root_ids)
        context_nodes = self.apply_taint_scores(context_nodes, taint_scores)

        return self.assemble_from_nodes(repo_path, context_nodes)

    def _render_context(self, repo_path: Path, nodes: list[CodeContextNode]) -> tuple[str, int]:
        """Render text context for a finding and enforce token budget.

        Args:
            repo_path: Path to the repository root.
            nodes: Context nodes to render.

        Returns:
            Tuple of rendered context text and token count.
        """

        _LOGGER.debug("Rendering context for %d nodes", len(nodes))

        nodes = self.ranking_strategy.rank_nodes(nodes)

        # First pass to determine which lines to read, then read each file once and cache lines.
        file_lines_to_read: dict[Path, set[int]] = defaultdict(set)
        for node in nodes:
            for line_number in range(node.line_start, node.line_end + 1):
                file_lines_to_read[node.file_path].add(line_number)

        # Second pass to read lines
        read_lines: dict[Path, dict[int, str]] = defaultdict(dict)
        for file_path, line_numbers in file_lines_to_read.items():
            lines = (
                (repo_path / file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
            )
            for line_number in line_numbers:
                read_lines[file_path][line_number] = self._sanitize_line(lines[line_number - 1])

        # Third pass to build context parts while enforcing token budget
        parts: list[str] = []
        lines_to_keep: dict[Path, set[int]] = defaultdict(set)
        for node in nodes:
            snippet_lines: list[str] = []
            for line_number in range(node.line_start, node.line_end + 1):
                if line_number in lines_to_keep[node.file_path]:
                    continue
                line = read_lines[node.file_path][line_number]
                if line:
                    lines_to_keep[node.file_path].add(line_number)
                    snippet_lines.append(line)

            snippet = "\n".join(snippet_lines)

            candidate_text = "\n".join([*parts, snippet])
            candidate_tokens = self._estimate_tokens(candidate_text)
            if candidate_tokens > self.token_budget:
                # exclude current node and stop processing further nodes, as we run out of budget
                for line_number in range(node.line_start, node.line_end + 1):
                    if line_number in lines_to_keep[node.file_path]:
                        lines_to_keep[node.file_path].remove(line_number)
                break
            parts.append(snippet)

        # Forth pass to build final context text with only the lines that fit in the token budget
        parts = []
        for file_to_read, line_to_keep in lines_to_keep.items():
            for line_number in sorted(line_to_keep):
                parts.append(read_lines[file_to_read][line_number])

        candidate_text = "\n".join(parts)

        if not candidate_text:
            _LOGGER.warning("Empty snippet for project %s", repo_path)

        return candidate_text, self._estimate_tokens(candidate_text)

    @staticmethod
    def _sanitize_line(line: str) -> str:
        """Trim a line to remove leading/trailing whitespace and comment markers."""

        if "#" not in line:
            return line.rstrip()
        return line[: line.index("#")].rstrip()

    def _estimate_tokens(self, text: str) -> int:
        """Estimate token usage for the supplied text.

        Args:
            text: Input text to estimate.

        Returns:
            Estimated token count.
        """

        estimator = self.token_estimator
        if estimator is not None:
            return estimator(text)
        return max(1, len(text) // 3) if text else 0
