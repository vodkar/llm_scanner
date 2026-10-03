import ast
import logging
import re
from collections import defaultdict, deque
from collections.abc import Callable
from pathlib import Path
from typing import Final, NamedTuple

from pydantic import BaseModel, ConfigDict, PrivateAttr

from models.base import NodeID
from models.context import CodeContextNode, Context, FileSpans, RootContext, SnippetSegment
from models.edges.call_graph import CallGraphRelationshipType
from repositories.context import ContextRepository
from repositories.queries import code_traversal_relationship_types
from services.context_assembler.node_filters import is_test_path, text_uses_test_framework
from services.context_assembler.source_map import (
    RenderedLine,
    build_source_map,
    has_nonstandard_line_breaks,
)
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

_ROOT_MARKER: Final[str] = (
    "# ===== ROOT {index}/{total}: {file_path}:{line_start}-{line_end} | code under analysis ====="
)
_CONTEXT_MARKER: Final[str] = (
    "# ----- CONTEXT for ROOT {index} | reference only: related callers, callees "
    "and definitions -----"
)
_FILE_MARKER: Final[str] = "# file: {file_path}"

# Incoming edges of these types count toward a node's fan-in for hub damping.
# Outgoing calls and parameter/data-flow edges do not make a function a hub.
_FANIN_RELATIONSHIP_TYPES: Final[frozenset[str]] = frozenset(
    {CallGraphRelationshipType.CALLS, CallGraphRelationshipType.CALLED_BY}
)

type LinesByFile = dict[Path, set[int]]


class _RootGroup(NamedTuple):
    """Depth-0 nodes of one file whose line spans overlap, rendered as one root."""

    file_path: Path
    line_start: int
    line_end: int
    node_ids: frozenset[NodeID]


class _RenderedContext(NamedTuple):
    text: str
    source_map: list[SnippetSegment]
    roots: list[RootContext]


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
    hub_fanin_threshold: int = 8

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
        the root. We identify hubs by fan-in (distinct incoming call-graph
        sources), not total degree, so a function with many call sites or
        parameters but few callers stays transit. We then recompute root
        reachability with hubs removed as transit, and keep only roots, the
        still-reachable component, and the hub nodes themselves.
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
        callers: dict[NodeID, set[NodeID]] = defaultdict(set)
        for src, dst, rel_type in edges:
            if src == dst or src not in node_ids or dst not in node_ids:
                continue
            adjacency[src].add(dst)
            adjacency[dst].add(src)
            if rel_type in _FANIN_RELATIONSHIP_TYPES:
                callers[dst].add(src)

        hubs: set[NodeID] = {
            node.identifier
            for node in context_nodes
            if str(node.identifier) not in root_set
            and len(callers.get(node.identifier, ())) >= self.hub_fanin_threshold
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
        rendered = self._render_context(repo_path, cloned_nodes)

        return Context(
            description="Finding from spans query",
            context_text=rendered.text,
            token_count=self._estimate_tokens(rendered.text) if rendered.text else 0,
            source_map=rendered.source_map,
            roots=rendered.roots,
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

    def _render_context(self, repo_path: Path, nodes: list[CodeContextNode]) -> _RenderedContext:
        """Render per-root sections for a finding within the token budget.

        Nodes are ranked and selected with budgeted path-fill as a whole; each
        selected non-root node is then attributed to its nearest root group, and
        every root is rendered followed by its own context section.

        Args:
            repo_path: Path to the repository root.
            nodes: Context nodes to render.

        Returns:
            Rendered text, its snippet source map and the structured per-root split.
        """

        _LOGGER.debug("Rendering context for %d nodes", len(nodes))

        nodes = self.ranking_strategy.rank_nodes(nodes)
        if not nodes:
            return _RenderedContext("", [], [])

        full_lines, read_lines, unmappable_files = self._read_node_lines(repo_path, nodes)
        adjacency = self._build_path_fill_adjacency(nodes)
        selected_ids = self._select_nodes_with_path_fill(nodes, read_lines, adjacency)
        groups = self._group_root_nodes(nodes)

        if groups:
            rendered_lines, roots = self._render_root_sections(
                nodes, groups, selected_ids, adjacency, full_lines, read_lines
            )
        else:
            lines_to_keep = self._complete_structure(
                full_lines, self._lines_for_selection(nodes, selected_ids), {}
            )
            self._ensure_line_text(read_lines, full_lines, lines_to_keep)
            rendered_lines, roots = self._render_lines(read_lines, lines_to_keep), []

        text = "\n".join(line_text for _, _, line_text in rendered_lines)
        if not text:
            _LOGGER.warning("Empty snippet for project %s", repo_path)

        return _RenderedContext(
            text,
            [
                segment
                for segment in build_source_map(rendered_lines)
                if segment.file_path not in unmappable_files
            ],
            roots,
        )

    def _read_node_lines(
        self, repo_path: Path, nodes: list[CodeContextNode]
    ) -> tuple[dict[Path, list[str]], dict[Path, dict[int, str]], set[Path]]:
        """Read source files of ``nodes``.

        Returns:
            Full raw lines per file, sanitized text of node-covered lines per file,
            and files whose line numbering cannot be mapped back to analyzers.
        """

        file_lines_to_read: LinesByFile = defaultdict(set)
        for node in nodes:
            file_lines_to_read[node.file_path].update(range(node.line_start, node.line_end + 1))

        full_lines: dict[Path, list[str]] = {}
        read_lines: dict[Path, dict[int, str]] = defaultdict(dict)
        unmappable_files: set[Path] = set()
        for file_path, line_numbers in file_lines_to_read.items():
            try:
                text = (repo_path / file_path).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                _LOGGER.warning("Cannot read source file %s; skipping its lines", file_path)
                continue
            if has_nonstandard_line_breaks(text):
                unmappable_files.add(file_path)
            # read_text() already normalized \r\n and \r to \n; splitlines() would
            # also split on \x0c etc., which analyzers and the CPG do not.
            lines = text.split("\n")
            full_lines[file_path] = lines
            for line_number in line_numbers:
                if line_number > len(lines):
                    continue
                read_lines[file_path][line_number] = self._sanitize_line(lines[line_number - 1])
        return full_lines, read_lines, unmappable_files

    @classmethod
    def _group_root_nodes(cls, nodes: list[CodeContextNode]) -> list[_RootGroup]:
        """Merge depth-0 nodes with overlapping line spans in a file into root groups.

        A function root and the variable/call nodes nested inside it become one
        group, while two separate functions stay distinct roots. Groups are
        ordered by first file appearance, then by line.
        """

        roots_by_file: dict[Path, list[CodeContextNode]] = defaultdict(list)
        for node in nodes:
            if node.depth == 0:
                roots_by_file[node.file_path].append(node)

        groups: list[_RootGroup] = []
        for file_path, file_roots in roots_by_file.items():
            pending: list[CodeContextNode] = []
            for node in sorted(file_roots, key=lambda n: (n.line_start, n.line_end)):
                if pending and node.line_start > max(n.line_end for n in pending):
                    groups.append(cls._make_root_group(file_path, pending))
                    pending = []
                pending.append(node)
            groups.append(cls._make_root_group(file_path, pending))
        return groups

    @classmethod
    def _make_root_group(cls, file_path: Path, nodes: list[CodeContextNode]) -> _RootGroup:
        return _RootGroup(
            file_path=file_path,
            line_start=min(node.line_start for node in nodes),
            line_end=max(node.line_end for node in nodes),
            node_ids=frozenset(node.identifier for node in nodes),
        )

    @classmethod
    def _assign_root_owners(
        cls,
        nodes: list[CodeContextNode],
        groups: list[_RootGroup],
        selected_ids: set[NodeID],
        adjacency: dict[NodeID, set[NodeID]],
    ) -> dict[NodeID, int]:
        """Map every selected node to the index of the root group it serves.

        A multi-source BFS restricted to the selected nodes attributes each node
        to its nearest root, so a context node rendered under a root is linked to
        it through rendered code. Neighbors are visited in sorted order to keep
        ties deterministic. Nodes not connected to any root fall back to the
        closest root in the same file, else to the first root.
        """

        owners: dict[NodeID, int] = {}
        queue: deque[NodeID] = deque()
        for index, group in enumerate(groups):
            for node_id in sorted(group.node_ids):
                owners[node_id] = index
                queue.append(node_id)

        while queue:
            current = queue.popleft()
            for neighbor in sorted(adjacency.get(current, ())):
                if neighbor in owners or neighbor not in selected_ids:
                    continue
                owners[neighbor] = owners[current]
                queue.append(neighbor)

        for node in nodes:
            if node.identifier in selected_ids and node.identifier not in owners:
                owners[node.identifier] = cls._closest_group_index(node, groups)
        return owners

    @staticmethod
    def _closest_group_index(node: CodeContextNode, groups: list[_RootGroup]) -> int:
        same_file = [
            (abs(node.line_start - group.line_start), index)
            for index, group in enumerate(groups)
            if group.file_path == node.file_path
        ]
        return min(same_file)[1] if same_file else 0

    def _render_root_sections(
        self,
        nodes: list[CodeContextNode],
        groups: list[_RootGroup],
        selected_ids: set[NodeID],
        adjacency: dict[NodeID, set[NodeID]],
        full_lines: dict[Path, list[str]],
        read_lines: dict[Path, dict[int, str]],
    ) -> tuple[list[RenderedLine], list[RootContext]]:
        """Render each root group followed by the context attributed to it.

        Root lines never repeat inside a context section (of any root), while the
        enclosing ``def``/``class`` headers are completed per section so each
        section is structurally coherent on its own.
        """

        owners = self._assign_root_owners(nodes, groups, selected_ids, adjacency)
        all_root_lines = self._lines_for_selection(
            nodes, {node_id for group in groups for node_id in group.node_ids}
        )

        rendered: list[RenderedLine] = []
        roots: list[RootContext] = []
        seen_boilerplate: set[str] = set()
        for index, group in enumerate(groups):
            root_lines = self._lines_for_selection(nodes, set(group.node_ids))
            root_lines = self._complete_structure(full_lines, root_lines, root_lines)
            context_ids = {
                node_id
                for node_id, owner in owners.items()
                if owner == index and node_id not in group.node_ids
            }
            context_lines: LinesByFile = {
                file_path: kept
                for file_path, lines in self._lines_for_selection(nodes, context_ids).items()
                if (kept := lines - all_root_lines.get(file_path, set()))
            }
            context_lines = self._complete_structure(full_lines, context_lines, {})
            self._ensure_line_text(read_lines, full_lines, root_lines)
            self._ensure_line_text(read_lines, full_lines, context_lines)

            root_rendered = self._render_lines(read_lines, root_lines, seen_boilerplate)
            context_rendered = self._with_file_markers(
                self._render_lines(read_lines, context_lines, seen_boilerplate)
            )
            number = index + 1
            rendered.append(
                self._marker_line(
                    _ROOT_MARKER.format(
                        index=number,
                        total=len(groups),
                        file_path=group.file_path,
                        line_start=group.line_start,
                        line_end=group.line_end,
                    )
                )
            )
            rendered.extend(root_rendered)
            if context_rendered:
                rendered.append(self._marker_line(_CONTEXT_MARKER.format(index=number)))
                rendered.extend(context_rendered)
            roots.append(
                RootContext(
                    file_path=group.file_path,
                    line_start=group.line_start,
                    line_end=group.line_end,
                    code="\n".join(text for _, _, text in root_rendered),
                    context="\n".join(text for _, _, text in context_rendered),
                )
            )
        return rendered, roots

    @classmethod
    def _with_file_markers(cls, rendered_lines: list[RenderedLine]) -> list[RenderedLine]:
        """Prefix each run of lines from one file with a ``# file:`` marker line."""

        result: list[RenderedLine] = []
        current_file: Path | None = None
        for line in rendered_lines:
            if line[0] != current_file:
                current_file = line[0]
                result.append(cls._marker_line(_FILE_MARKER.format(file_path=current_file)))
            result.append(line)
        return result

    @classmethod
    def _marker_line(cls, text: str) -> RenderedLine:
        return (None, 0, text)

    def _select_nodes_with_path_fill(
        self,
        ranked_nodes: list[CodeContextNode],
        read_lines: dict[Path, dict[int, str]],
        adjacency: dict[NodeID, set[NodeID]] | None = None,
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

        if adjacency is None:
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

    @classmethod
    def _complete_structure(
        cls,
        full_lines: dict[Path, list[str]],
        lines_to_keep: dict[Path, set[int]],
        root_lines: dict[Path, set[int]],
    ) -> dict[Path, set[int]]:
        """Make each file's kept-line set structurally coherent (issue D).

        For every kept body line, the enclosing ``def``/``class`` header lines are
        added (so methods/statements never render without their scope); headers of
        scopes with no kept body line are dropped (so no bare ``class X:`` is
        emitted), except lines belonging to a root node, which are always kept.
        Files that do not parse as Python are returned unchanged.
        """

        completed: dict[Path, set[int]] = {}
        for file_path, kept in lines_to_keep.items():
            raw = full_lines.get(file_path)
            scopes = cls._parse_file_scopes("\n".join(raw)) if raw else None
            if scopes is None:
                completed[file_path] = set(kept)
                continue

            protected = root_lines.get(file_path, set())
            result = set(kept)
            for header_lines, body_start, body_end in scopes:
                if any(body_start <= line <= body_end for line in kept):
                    result |= header_lines
                else:
                    result -= header_lines - protected
            completed[file_path] = result
        return completed

    @staticmethod
    def _parse_file_scopes(
        source: str,
    ) -> list[tuple[frozenset[int], int, int]] | None:
        """Return ``(header_lines, body_start, body_end)`` for each def/class scope.

        ``header_lines`` covers decorators and the signature up to the first body
        statement; ``body_start``/``body_end`` bound the scope body. Returns
        ``None`` when the source is not parseable Python.
        """

        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            return None

        scopes: list[tuple[frozenset[int], int, int]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                continue
            if not node.body:
                continue
            start = node.lineno
            for decorator in node.decorator_list:
                start = min(start, decorator.lineno)
            first_body = node.body[0]
            header_lines = frozenset(range(start, first_body.lineno))
            body_end = node.end_lineno or first_body.lineno
            scopes.append((header_lines, first_body.lineno, body_end))
        return scopes

    @classmethod
    def _ensure_line_text(
        cls,
        read_lines: dict[Path, dict[int, str]],
        full_lines: dict[Path, list[str]],
        lines_to_keep: dict[Path, set[int]],
    ) -> None:
        """Populate ``read_lines`` with sanitized text for any added header lines."""

        for file_path, line_numbers in lines_to_keep.items():
            raw = full_lines.get(file_path, [])
            for line_number in line_numbers:
                if line_number not in read_lines[file_path] and 1 <= line_number <= len(raw):
                    read_lines[file_path][line_number] = cls._sanitize_line(raw[line_number - 1])

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

    @classmethod
    def _render_lines(
        cls,
        read_lines: dict[Path, dict[int, str]],
        lines_to_keep: dict[Path, set[int]],
        seen_boilerplate: set[str] | None = None,
    ) -> list[RenderedLine]:
        """Return rendered lines with provenance, in output order.

        Empty lines are skipped and exact-duplicate module-level boilerplate
        lines (e.g. repeated ``logger = logging.getLogger(__name__)`` from
        different files) are collapsed to their first occurrence; all other
        lines are kept verbatim. Pass a shared ``seen_boilerplate`` set to
        collapse boilerplate across several rendered sections; it is updated
        in place.
        """

        rendered: list[RenderedLine] = []
        if seen_boilerplate is None:
            seen_boilerplate = set()
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
                rendered.append((file_path, line_number, line))
        return rendered

    @classmethod
    def _render_text(
        cls,
        read_lines: dict[Path, dict[int, str]],
        lines_to_keep: dict[Path, set[int]],
    ) -> str:
        """Render the final text from the chosen line set per file."""

        return "\n".join(text for _, _, text in cls._render_lines(read_lines, lines_to_keep))

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
