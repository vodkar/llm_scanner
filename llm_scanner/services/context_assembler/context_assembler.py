import logging
from collections import defaultdict, deque
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from models.base import NodeID
from models.context import CodeContextNode, Context, FileSpans
from repositories.context import ContextRepository
from services.ranking.ranking import (
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
        _LOGGER.info(
            "Fetched %d context nodes neighborhood for %d root IDs",
            len(context_nodes),
            len(root_ids),
        )
        return context_nodes

    def fetch_taint_scores(self, root_ids: list[str]) -> dict[NodeID, float]:
        """Fetch backward-taint scores for the supplied root node IDs."""

        if not root_ids:
            return {}
        result = self.context_repository.fetch_taint_sources(root_ids)
        _LOGGER.info("Fetched taint scores for %d root IDs", len(result))
        return result

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

        Ranked nodes are augmented with the shortest CPG path back to a root
        (``depth==0``) node so that intermediate calls or data-flow nodes are
        not silently dropped between two prioritized snippets. When the budget
        forces a choice, the lowest-scored leaf nodes are evicted before any
        path-fill companion is discarded.

        Args:
            repo_path: Path to the repository root.
            nodes: Context nodes to render.

        Returns:
            Tuple of rendered context text and token count.
        """

        _LOGGER.debug("Rendering context for %d nodes", len(nodes))

        nodes = self.ranking_strategy.rank_nodes(nodes)
        if not nodes:
            return "", 0

        file_lines_to_read: dict[Path, set[int]] = defaultdict(set)
        for node in nodes:
            for line_number in range(node.line_start, node.line_end + 1):
                file_lines_to_read[node.file_path].add(line_number)

        read_lines: dict[Path, dict[int, str]] = defaultdict(dict)
        for file_path, line_numbers in file_lines_to_read.items():
            lines = (
                (repo_path / file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
            )
            for line_number in line_numbers:
                read_lines[file_path][line_number] = self._sanitize_line(lines[line_number - 1])

        selected_ids = self._select_nodes_with_path_fill(nodes, read_lines)

        lines_to_keep = self._lines_for_selection(nodes, selected_ids)
        candidate_text = self._render_text(read_lines, lines_to_keep)

        if not candidate_text:
            _LOGGER.warning("Empty snippet for project %s", repo_path)

        return candidate_text, self._estimate_tokens(candidate_text)

    def _select_nodes_with_path_fill(
        self,
        ranked_nodes: list[CodeContextNode],
        read_lines: dict[Path, dict[int, str]],
    ) -> set[NodeID]:
        """Return node IDs to render, preserving CPG connectivity to roots.

        Roots (``depth==0``) are pinned. For each non-root candidate (in the
        strategy's sort order) we walk the parent chain produced by a single
        multi-source BFS back to its nearest root, then include the candidate
        plus any not-yet-selected ancestors **only if** the resulting line set
        still fits the token budget. No eviction.
        """

        if not ranked_nodes:
            return set()

        root_ids: set[NodeID] = {n.identifier for n in ranked_nodes if n.depth == 0}

        adjacency = self._build_path_fill_adjacency(ranked_nodes)
        _LOGGER.debug(
            "Built adjacency with %d entries for %d nodes", len(adjacency), len(ranked_nodes)
        )
        parent_to_root = self._bfs_parents_from_roots(root_ids, adjacency)
        _LOGGER.debug("Computed parent_to_root for %d nodes", len(parent_to_root))

        selected_ids: set[NodeID] = set(root_ids)

        for node in ranked_nodes:
            node_id = node.identifier
            if node_id in selected_ids:
                continue

            chain = self._companion_chain(node_id, selected_ids, parent_to_root)
            new_ids = chain - selected_ids
            if not new_ids:
                continue

            trial_lines = self._lines_for_selection(ranked_nodes, selected_ids | new_ids)
            trial_tokens = self._estimate_tokens(self._render_text(read_lines, trial_lines))
            if trial_tokens <= self.token_budget:
                selected_ids |= new_ids

        _LOGGER.debug("Selected %d nodes after path-fill", len(selected_ids))
        return selected_ids

    def _build_path_fill_adjacency(
        self, ranked_nodes: list[CodeContextNode]
    ) -> dict[NodeID, set[NodeID]]:
        """Fetch edges among the fetched neighborhood and build an undirected map."""

        fetched_ids: set[NodeID] = {n.identifier for n in ranked_nodes}
        edges = self.context_repository.fetch_neighborhood_edges([str(nid) for nid in fetched_ids])
        adjacency: dict[NodeID, set[NodeID]] = defaultdict(set)
        for src, dst, _ in edges:
            if src == dst or src not in fetched_ids or dst not in fetched_ids:
                continue
            adjacency[src].add(dst)
            adjacency[dst].add(src)
        return adjacency

    @staticmethod
    def _bfs_parents_from_roots(
        root_ids: set[NodeID],
        adjacency: dict[NodeID, set[NodeID]],
    ) -> dict[NodeID, NodeID | None]:
        """Run a single multi-source BFS to map every reachable node to its parent.

        ``parent[root] = None`` for each seed. For every other reachable node
        the value is the neighbor through which BFS first discovered it — i.e.,
        the next hop on the shortest path back toward the nearest root.
        Unreachable nodes are absent.
        """

        parent: dict[NodeID, NodeID | None] = {root_id: None for root_id in root_ids}
        queue: deque[NodeID] = deque(root_ids)
        while queue:
            current = queue.popleft()
            for neighbor in adjacency.get(current, ()):
                if neighbor in parent:
                    continue
                parent[neighbor] = current
                queue.append(neighbor)
        return parent

    @staticmethod
    def _companion_chain(
        node_id: NodeID,
        selected: set[NodeID],
        parent_to_root: dict[NodeID, NodeID | None],
    ) -> set[NodeID]:
        """Walk the parent chain from ``node_id`` toward a root.

        Returns ``{node_id} ∪ ancestors`` collected along the way. The walk
        stops at the first node that is already in ``selected`` (typically a
        root) — that node is **not** added because it is already selected.
        Disconnected nodes (absent from ``parent_to_root``) yield ``{node_id}``.
        """

        chain: set[NodeID] = {node_id}
        if node_id not in parent_to_root:
            return chain
        cursor: NodeID | None = parent_to_root.get(node_id)
        while cursor is not None and cursor not in selected:
            chain.add(cursor)
            cursor = parent_to_root.get(cursor)
        return chain

    @staticmethod
    def _lines_for_selection(
        ranked_nodes: list[CodeContextNode],
        selected_ids: set[NodeID],
    ) -> dict[Path, set[int]]:
        """Return per-file line numbers covered by the selected node set."""

        result: dict[Path, set[int]] = defaultdict(set)
        for node in ranked_nodes:
            if node.identifier not in selected_ids:
                continue
            for line_number in range(node.line_start, node.line_end + 1):
                result[node.file_path].add(line_number)
        return result

    @staticmethod
    def _render_text(
        read_lines: dict[Path, dict[int, str]],
        lines_to_keep: dict[Path, set[int]],
    ) -> str:
        """Render the final text from the chosen line set per file."""

        parts: list[str] = []
        for file_path, lines in lines_to_keep.items():
            for line_number in sorted(lines):
                parts.append(read_lines[file_path][line_number])
        return "\n".join(parts)

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
