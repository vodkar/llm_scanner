import logging
import re
from collections import defaultdict, deque
from collections.abc import Callable
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, PrivateAttr

from models.base import NodeID
from models.context import CodeContextNode, Context, FileSpans
from repositories.context import ContextRepository
from repositories.queries import code_traversal_relationship_types
from services.context_assembler.node_filters import is_test_path, text_uses_test_framework
from services.ranking.ranking import (
    ContextNodeRankingStrategy,
)

TokenEstimator = Callable[[str], int]
_LOGGER = logging.getLogger(__name__)

# Module-level boilerplate whose identical lines recur across files and carry no
# security signal; only exact-duplicate matches are collapsed during rendering.
_BOILERPLATE_LINE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^\s*_?[A-Za-z][\w.]*\s*=\s*logging\.getLogger"),
)


class ContextAssemblerService(BaseModel):
    """Assemble LLM context for vulnerability findings."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path
    context_repository: ContextRepository | None = None
    max_call_depth: int
    token_budget: int
    snippet_cache_max_entries: int = 10000
    token_estimator: TokenEstimator | None = None
    ranking_strategy: ContextNodeRankingStrategy
    cached_neighborhood_edges: list[tuple[NodeID, NodeID, str]] | None = None
    exclude_test_nodes: bool = True
    damp_call_graph_hubs: bool = True
    hub_fanin_threshold: int = 12

    _test_file_cache: dict[Path, bool] = PrivateAttr(default_factory=dict)

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

    def _require_repo(self) -> ContextRepository:
        """Return the Neo4j-backed repository, asserting that it is configured.

        Phase 2 (cached) flows must never reach methods that hit Neo4j.
        """

        if self.context_repository is None:
            raise RuntimeError(
                "ContextAssemblerService.context_repository is not configured; "
                "this method requires a live Neo4j connection."
            )
        return self.context_repository

    def fetch_root_ids_for_spans(self, files_spans: list[FileSpans]) -> list[str]:
        """Return unique root node IDs overlapping the supplied file spans."""

        self._validate_file_spans(files_spans)

        spans_nodes = self._require_repo().fetch_code_nodes_by_file_spans(
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

        repo = self._require_repo()
        if requires_edge_paths:
            context_nodes = repo.fetch_code_neighborhood_with_edge_paths(
                root_ids,
                self.max_call_depth,
            )
        else:
            context_nodes = repo.fetch_code_neighborhood_batch(
                root_ids,
                self.max_call_depth,
            )

        if self.exclude_test_nodes:
            context_nodes = self._filter_test_nodes(root_ids, context_nodes)

        if self.damp_call_graph_hubs:
            context_nodes = self._prune_hub_mediated_nodes(repo, root_ids, context_nodes)

        context_nodes = self._merge_enclosing_class_nodes(repo, root_ids, context_nodes)
        _LOGGER.info(
            "Fetched %d context nodes neighborhood for %d root IDs",
            len(context_nodes),
            len(root_ids),
        )
        return context_nodes

    def _filter_test_nodes(
        self,
        root_ids: list[str],
        context_nodes: list[CodeContextNode],
    ) -> list[CodeContextNode]:
        """Drop non-root nodes that belong to test code.

        Root nodes (those whose identifier is in ``root_ids``) are always kept,
        even when they live in a test file. A non-root node is dropped when its
        path/name looks like a test (:func:`is_test_path`) or its source file
        uses a known test framework (:meth:`_file_uses_test_framework`).
        """

        root_set = set(root_ids)
        kept = [
            node
            for node in context_nodes
            if str(node.identifier) in root_set or not self._is_test_node(node)
        ]
        dropped = len(context_nodes) - len(kept)
        if dropped:
            _LOGGER.info("Excluded %d test-code nodes from the neighborhood", dropped)
        return kept

    def _is_test_node(self, node: CodeContextNode) -> bool:
        """Return whether a node is test code by path/name or file content."""

        if is_test_path(node.file_path, node.name):
            return True
        return self._file_uses_test_framework(node.file_path)

    def _file_uses_test_framework(self, file_path: Path) -> bool:
        """Return whether the node's source file imports/uses a test framework.

        The result is memoized per file path. Unreadable files are treated as
        non-test (and cached as such).
        """

        cached = self._test_file_cache.get(file_path)
        if cached is not None:
            return cached

        try:
            text = (self.project_root / file_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            self._test_file_cache[file_path] = False
            return False

        result = text_uses_test_framework(text)
        self._test_file_cache[file_path] = result
        return result

    def _prune_hub_mediated_nodes(
        self,
        repo: ContextRepository,
        root_ids: list[str],
        context_nodes: list[CodeContextNode],
    ) -> list[CodeContextNode]:
        """Drop non-root nodes reachable from a root only through a fan-in hub.

        High-fan-in utilities (loggers, i18n ``_``, ``flash``-style helpers) are
        called from many unrelated functions; undirected BFS then pulls every
        caller into the neighborhood even though it shares only that utility with
        the root. We identify hubs by degree over the call/data-flow edges,
        recompute root reachability with hubs removed as transit, and keep only
        roots, the still-reachable component, and the hub nodes themselves.
        """

        if len(context_nodes) <= 1:
            return context_nodes

        root_set = set(root_ids)
        node_ids = {node.identifier for node in context_nodes}
        edges = repo.fetch_neighborhood_edges(
            [str(nid) for nid in node_ids],
            edge_types=code_traversal_relationship_types(),
        )

        adjacency: dict[NodeID, set[NodeID]] = defaultdict(set)
        for src, dst, _ in edges:
            if src == dst or src not in node_ids or dst not in node_ids:
                continue
            adjacency[src].add(dst)
            adjacency[dst].add(src)

        hubs: set[NodeID] = {
            node.identifier
            for node in context_nodes
            if str(node.identifier) not in root_set
            and len(adjacency.get(node.identifier, ())) >= self.hub_fanin_threshold
        }
        if not hubs:
            return context_nodes

        root_node_ids: set[NodeID] = {
            node.identifier for node in context_nodes if str(node.identifier) in root_set
        }
        reachable = self._reachable_excluding(root_node_ids, adjacency, blocked=hubs)

        kept = [
            node
            for node in context_nodes
            if node.identifier in root_node_ids
            or node.identifier in reachable
            or node.identifier in hubs
        ]
        dropped = len(context_nodes) - len(kept)
        if dropped:
            _LOGGER.info(
                "Pruned %d hub-mediated nodes (%d hubs, fan-in >= %d)",
                dropped,
                len(hubs),
                self.hub_fanin_threshold,
            )
        return kept

    @staticmethod
    def _reachable_excluding(
        seeds: set[NodeID],
        adjacency: dict[NodeID, set[NodeID]],
        *,
        blocked: set[NodeID],
    ) -> set[NodeID]:
        """Return nodes reachable from ``seeds`` without traversing ``blocked``.

        Seeds are always included; blocked nodes are never expanded through (a
        seed is assumed not to be blocked).
        """

        reachable: set[NodeID] = set(seeds)
        queue: deque[NodeID] = deque(seeds)
        while queue:
            current = queue.popleft()
            for neighbor in adjacency.get(current, ()):
                if neighbor in reachable or neighbor in blocked:
                    continue
                reachable.add(neighbor)
                queue.append(neighbor)
        return reachable

    @staticmethod
    def _merge_enclosing_class_nodes(
        repo: ContextRepository,
        root_ids: list[str],
        context_nodes: list[CodeContextNode],
    ) -> list[CodeContextNode]:
        """Append enclosing-class header nodes not already present.

        CONTAINS edges are excluded from neighborhood BFS, so the enclosing
        ``class X(...):`` header is fetched separately and merged in, keeping the
        shallowest depth when a class node is already part of the neighborhood.
        """

        class_nodes = repo.fetch_enclosing_class_nodes(root_ids)
        if not class_nodes:
            return context_nodes

        existing: dict[NodeID, CodeContextNode] = {node.identifier: node for node in context_nodes}
        additions: list[CodeContextNode] = []
        for class_node in class_nodes:
            current = existing.get(class_node.identifier)
            if current is None:
                additions.append(class_node)
                continue
            current.depth = min(current.depth, class_node.depth)
        return [*context_nodes, *additions]

    def fetch_taint_scores(self, root_ids: list[str]) -> dict[NodeID, float]:
        """Fetch backward-taint scores for the supplied root node IDs."""

        if not root_ids:
            return {}
        result = self._require_repo().fetch_taint_sources(root_ids)
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
        if self.ranking_strategy.requires_taint_scores:
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
        if not nodes:
            return "", 0

        file_lines_to_read: dict[Path, set[int]] = defaultdict(set)
        for node in nodes:
            for line_number in range(node.line_start, node.line_end + 1):
                file_lines_to_read[node.file_path].add(line_number)

        read_lines: dict[Path, dict[int, str]] = defaultdict(dict)
        for file_path, line_numbers in file_lines_to_read.items():
            try:
                text = (repo_path / file_path).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                _LOGGER.warning("Cannot read source file %s; skipping its lines", file_path)
                continue
            lines = text.splitlines()
            for line_number in line_numbers:
                if line_number > len(lines):
                    continue
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
        """Build an undirected adjacency map among the fetched neighborhood.

        When ``cached_neighborhood_edges`` is set (Phase 2 of the tuner cache
        flow), the edges are taken directly from the cache and no Neo4j call
        is made. Otherwise, ``context_repository`` must be set and is queried.
        """

        fetched_ids: set[NodeID] = {n.identifier for n in ranked_nodes}
        if self.cached_neighborhood_edges is not None:
            edges: list[tuple[NodeID, NodeID, str]] = self.cached_neighborhood_edges
        elif self.context_repository is not None:
            edges = self.context_repository.fetch_neighborhood_edges(
                [str(nid) for nid in fetched_ids]
            )
        else:
            raise RuntimeError(
                "ContextAssemblerService requires either context_repository or "
                "cached_neighborhood_edges to build the path-fill adjacency."
            )

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
        """Render the final text from the chosen line set per file.

        Exact-duplicate module-level boilerplate lines (e.g. repeated
        ``logger = logging.getLogger(__name__)`` from different files) are
        collapsed to their first occurrence; all other lines are kept verbatim.
        """

        parts: list[str] = []
        seen_boilerplate: set[str] = set()
        for file_path, lines in lines_to_keep.items():
            file_lines = read_lines.get(file_path, {})
            for line_number in sorted(lines):
                line = file_lines.get(line_number, "").rstrip()
                if not line:
                    continue
                if any(pattern.match(line) for pattern in _BOILERPLATE_LINE_PATTERNS):
                    if line in seen_boilerplate:
                        continue
                    seen_boilerplate.add(line)
                parts.append(line)
        return "\n".join(parts)

    @staticmethod
    def _sanitize_line(line: str) -> str:
        """Trim trailing whitespace and strip a trailing ``#`` comment.

        Only a ``#`` outside single/double quotes starts a comment, so string
        literals containing ``#`` (URLs, colors, regexes) are kept intact.
        """

        if "#" not in line:
            return line.rstrip()

        quote_char: str | None = None
        index = 0
        while index < len(line):
            char = line[index]
            if quote_char is not None:
                if char == "\\":
                    index += 2
                    continue
                if char == quote_char:
                    quote_char = None
            elif char in "'\"":
                quote_char = char
            elif char == "#":
                return line[:index].rstrip()
            index += 1
        return line.rstrip()

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
        return max(1, len(text) // 3)
