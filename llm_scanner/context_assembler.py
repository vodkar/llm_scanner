from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from typing import Any

from pydantic import BaseModel, ConfigDict, PrivateAttr

from models.context import CodeContextNode, ContextAssembly, FindingContext
from models.nodes.finding import BanditFindingNode, DlintFindingNode, FindingNode
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.context import ContextRepository

TokenEstimator = Callable[[str], int]
_LOGGER = logging.getLogger(__name__)
LOGGING_INTERVAL = 200
FULL_CONTEXT_NODE_KINDS: tuple[str, ...] = ("FunctionNode", "ClassNode", "CodeBlockNode")
PREFERRED_RENDER_NODE_KINDS: tuple[str, ...] = ("FunctionNode", "ClassNode")


class ContextAssemblerService(BaseModel):
    """Assemble LLM context for vulnerability findings."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path
    bandit_repository: BanditFindingsRepository
    dlint_repository: DlintFindingsRepository
    context_repository: ContextRepository
    max_call_depth: int = 3
    token_budget: int = 8192
    context_workers: int = 30
    snippet_cache_max_entries: int = 10000
    neighborhood_cache_max_entries: int = 2000
    token_estimator: TokenEstimator | None = None

    _cache_lock: Lock = PrivateAttr(default_factory=Lock)
    _file_lines_cache: dict[Path, list[str]] = PrivateAttr(default_factory=dict)
    _snippet_cache: dict[tuple[Path, int, int], str] = PrivateAttr(default_factory=dict)
    _neighborhood_cache: dict[tuple[int, tuple[str, ...]], list[dict[str, Any]]] = PrivateAttr(
        default_factory=dict
    )

    def assemble(self) -> ContextAssembly:
        """Build context objects for all analyzer findings.

        Returns:
            Context assembly with one entry per finding.
        """

        findings = self._collect_findings()

        if not findings:
            return ContextAssembly()

        finding_to_nodes, line_to_enclosing_nodes = self._load_finding_context_rows(findings)
        finding_inputs = [
            self._finding_input(
                finding=finding,
                finding_to_nodes=finding_to_nodes,
                line_to_enclosing_nodes=line_to_enclosing_nodes,
            )
            for finding in findings
        ]

        contexts = self._assemble_finding_inputs(finding_inputs)
        return ContextAssembly(findings=contexts)

    def assemble_for_vulnerability_span(
        self,
        *,
        target_file: Path,
        start_line: int,
        end_line: int,
        non_associated_limit: int = 0,
    ) -> tuple[ContextAssembly, ContextAssembly]:
        """Assemble context for findings whose code node spans overlap a target span.

        Args:
            target_file: File path for the vulnerable span.
            start_line: Start line of the vulnerable span.
            end_line: End line of the vulnerable span.
            non_associated_limit: Maximum non-associated findings to assemble.

        Returns:
            Tuple of (associated contexts, non-associated contexts).
        """

        if start_line < 1:
            raise ValueError("start_line must be >= 1")
        if end_line < start_line:
            raise ValueError("end_line must be >= start_line")

        findings = self._collect_findings()
        if not findings:
            return ContextAssembly(), ContextAssembly()

        finding_to_nodes, line_to_enclosing_nodes = self._load_finding_context_rows(findings)

        associated_inputs: list[
            tuple[FindingNode, list[dict[str, object]], list[dict[str, Any]]]
        ] = []
        non_associated_inputs: list[
            tuple[FindingNode, list[dict[str, object]], list[dict[str, Any]]]
        ] = []

        for finding in findings:
            finding_input = self._finding_input(
                finding=finding,
                finding_to_nodes=finding_to_nodes,
                line_to_enclosing_nodes=line_to_enclosing_nodes,
            )
            if self._finding_overlaps_span(
                finding=finding,
                reported_nodes=finding_input[1],
                enclosing_nodes=finding_input[2],
                target_file=target_file,
                start_line=start_line,
                end_line=end_line,
            ):
                associated_inputs.append(finding_input)
            else:
                non_associated_inputs.append(finding_input)

        associated_contexts = self._assemble_finding_inputs(associated_inputs)
        limited_non_associated = non_associated_inputs[: max(0, non_associated_limit)]
        non_associated_contexts = self._assemble_finding_inputs(limited_non_associated)

        return ContextAssembly(findings=associated_contexts), ContextAssembly(
            findings=non_associated_contexts
        )

    def _collect_findings(self) -> list[FindingNode]:
        """Collect all analyzer findings for the configured project root."""

        findings: list[FindingNode] = []
        findings.extend(self.bandit_repository.iter_findings_for_project(self.project_root))
        findings.extend(self.dlint_repository.iter_findings_for_project(self.project_root))
        return findings

    def _load_finding_context_rows(
        self,
        findings: list[FindingNode],
    ) -> tuple[
        dict[str, list[dict[str, object]]],
        dict[tuple[str, int], list[dict[str, Any]]],
    ]:
        """Load and index row data required to assemble finding contexts."""

        finding_ids: list[str] = [str(finding.identifier) for finding in findings]
        reported_rows = self.context_repository.fetch_reported_code_nodes(finding_ids)
        enclosing_rows = self.context_repository.fetch_code_nodes_by_file_lines(
            [
                {
                    "file_path": str(finding.file),
                    "line_number": finding.line_number,
                }
                for finding in findings
            ]
        )

        finding_to_nodes: dict[str, list[dict[str, object]]] = defaultdict(list)
        for row in reported_rows:
            finding_to_nodes[str(row["finding_id"])].append(row)

        line_to_enclosing_nodes: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for row in enclosing_rows:
            file_path = self._coerce_str(row.get("file_path"))
            line_number = self._coerce_int(row.get("line_number"))
            if file_path is None or line_number is None:
                continue
            line_to_enclosing_nodes[(file_path, line_number)].append(row)

        return finding_to_nodes, line_to_enclosing_nodes

    def _finding_input(
        self,
        *,
        finding: FindingNode,
        finding_to_nodes: dict[str, list[dict[str, object]]],
        line_to_enclosing_nodes: dict[tuple[str, int], list[dict[str, Any]]],
    ) -> tuple[FindingNode, list[dict[str, object]], list[dict[str, Any]]]:
        """Build reusable assembly input tuple for a single finding."""

        finding_id = str(finding.identifier)
        reported_nodes = finding_to_nodes.get(finding_id, [])
        enclosing_candidates = line_to_enclosing_nodes.get(
            (str(finding.file), finding.line_number),
            [],
        )
        return finding, reported_nodes, enclosing_candidates

    def _assemble_finding_inputs(
        self,
        finding_inputs: list[tuple[FindingNode, list[dict[str, object]], list[dict[str, Any]]]],
    ) -> list[FindingContext]:
        """Assemble contexts for precomputed finding input tuples."""

        if not finding_inputs:
            return []

        def _assemble_item(
            finding_input: tuple[FindingNode, list[dict[str, object]], list[dict[str, Any]]],
        ) -> FindingContext:
            finding, reported_nodes, enclosing_nodes = finding_input
            return self._assemble_finding_context(
                finding=finding,
                reported_nodes=reported_nodes,
                enclosing_nodes=enclosing_nodes,
            )

        contexts: list[FindingContext] = []
        with ThreadPoolExecutor(max_workers=self.context_workers) as executor:
            for index, context in enumerate(
                executor.map(_assemble_item, finding_inputs),
                start=1,
            ):
                contexts.append(context)
                if index % LOGGING_INTERVAL == 0:
                    _LOGGER.info("Assembled %d/%d finding contexts", index, len(finding_inputs))

        if contexts and len(contexts) % LOGGING_INTERVAL != 0:
            _LOGGER.info("Assembled %d/%d finding contexts", len(contexts), len(finding_inputs))

        return contexts

    def _finding_overlaps_span(
        self,
        *,
        finding: FindingNode,
        reported_nodes: list[dict[str, object]],
        enclosing_nodes: list[dict[str, Any]],
        target_file: Path,
        start_line: int,
        end_line: int,
    ) -> bool:
        """Check whether a finding's code node range overlaps a target span."""

        node_spans = self._finding_node_spans(
            finding=finding,
            reported_nodes=reported_nodes,
            enclosing_nodes=enclosing_nodes,
        )
        for node_file, node_start, node_end in node_spans:
            if not self._paths_match(node_file=node_file, target_file=target_file):
                continue
            if self._ranges_overlap(
                start_a=node_start,
                end_a=node_end,
                start_b=start_line,
                end_b=end_line,
            ):
                return True
        return False

    def _finding_node_spans(
        self,
        *,
        finding: FindingNode,
        reported_nodes: list[dict[str, object]],
        enclosing_nodes: list[dict[str, Any]],
    ) -> list[tuple[Path, int, int]]:
        """Return candidate node spans for a finding using reported rows and fallback."""

        spans: list[tuple[Path, int, int]] = []
        for row in reported_nodes:
            row_file = self._coerce_str(row.get("file_path"))
            line_start = self._coerce_int(row.get("line_start"))
            line_end = self._coerce_int(row.get("line_end"))
            if row_file is None or line_start is None or line_end is None:
                continue
            if line_end < line_start:
                continue
            spans.append((Path(row_file), line_start, line_end))

        if spans:
            return spans

        for row in enclosing_nodes:
            row_file = self._coerce_str(row.get("node_file_path") or row.get("file_path"))
            line_start = self._coerce_int(row.get("line_start"))
            line_end = self._coerce_int(row.get("line_end"))
            if row_file is None or line_start is None or line_end is None:
                continue
            if line_end < line_start:
                continue
            spans.append((Path(row_file), line_start, line_end))

        if spans:
            return spans

        return [(finding.file, finding.line_number, finding.line_number)]

    @staticmethod
    def _path_parts(path: Path) -> tuple[str, ...]:
        """Normalize path into comparable parts."""

        return tuple(part for part in path.as_posix().split("/") if part and part != ".")

    def _paths_match(self, *, node_file: Path, target_file: Path) -> bool:
        """Return whether two paths are equal by exact or suffix-aware matching."""

        if node_file == target_file:
            return True

        node_parts = self._path_parts(node_file)
        target_parts = self._path_parts(target_file)
        if node_parts == target_parts:
            return True

        if len(node_parts) >= len(target_parts):
            return tuple(node_parts[-len(target_parts) :]) == target_parts

        return tuple(target_parts[-len(node_parts) :]) == node_parts

    @staticmethod
    def _ranges_overlap(*, start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
        """Return whether two inclusive ranges overlap."""

        return max(start_a, start_b) <= min(end_a, end_b)

    def _assemble_finding_context(
        self,
        *,
        finding: FindingNode,
        reported_nodes: list[dict[str, object]],
        enclosing_nodes: list[dict[str, Any]],
    ) -> FindingContext:
        """Assemble context for a single finding.

        Args:
            finding: Finding node produced by analyzers.
            reported_nodes: Neo4j rows for nodes directly reported by the finding.

        Returns:
            Finding context with nodes and text.
        """

        start_node_ids = self._resolve_start_node_ids(
            reported_nodes=reported_nodes,
            enclosing_nodes=enclosing_nodes,
        )
        neighborhood_rows = self._expand_neighborhood(start_node_ids)

        nodes = self._build_context_nodes(neighborhood_rows)
        context_text, token_count = self._render_context(nodes)

        return FindingContext(
            finding_id=str(finding.identifier),
            finding_type=finding.__class__.__name__,
            file=finding.file,
            line_number=finding.line_number,
            description=self._finding_description(finding),
            nodes=nodes,
            context_text=context_text,
            token_count=token_count,
        )

    def _resolve_start_node_ids(
        self,
        *,
        reported_nodes: list[dict[str, object]],
        enclosing_nodes: list[dict[str, Any]],
    ) -> list[str]:
        """Resolve traversal start node IDs for a finding.

        Args:
            reported_nodes: Nodes directly linked by ``REPORTS``.
            enclosing_nodes: Nodes containing the finding file/line pair.

        Returns:
            Unique start node IDs, including promoted full-node IDs when available.
        """

        start_node_ids: set[str] = {
            str(row["code_id"]) for row in reported_nodes if row.get("code_id")
        }

        promoted_id = self._select_full_context_node_id(enclosing_nodes)
        if promoted_id is not None:
            start_node_ids.add(promoted_id)

        return sorted(start_node_ids)

    def _select_full_context_node_id(self, rows: list[dict[str, Any]]) -> str | None:
        """Pick the best enclosing code node for full snippet context."""

        best_id: str | None = None
        best_rank: tuple[int, int] | None = None

        for row in rows:
            node_id = self._coerce_str(row.get("id"))
            node_kind = self._coerce_str(row.get("node_kind"))
            line_start = self._coerce_int(row.get("line_start"))
            line_end = self._coerce_int(row.get("line_end"))
            if node_id is None or line_start is None or line_end is None:
                continue
            if line_end < line_start:
                continue

            span = line_end - line_start
            is_preferred_kind = int(node_kind in FULL_CONTEXT_NODE_KINDS)
            rank = (is_preferred_kind, span)

            if best_rank is None or rank > best_rank:
                best_rank = rank
                best_id = node_id

        return best_id

    def _expand_neighborhood(self, start_node_ids: list[str]) -> list[dict[str, Any]]:
        """Expand code nodes with BFS traversal across code relationships.

        Args:
            start_node_ids: List of code node identifiers.

        Returns:
            Unique code node rows ordered by traversal depth.
        """

        if not start_node_ids:
            return []

        unique_start_ids: tuple[str, ...] = tuple(sorted(set(start_node_ids)))
        cache_key = (self.max_call_depth, unique_start_ids)

        with self._cache_lock:
            cached_rows = self._neighborhood_cache.get(cache_key)
        if cached_rows is not None:
            return cached_rows

        neighborhood_rows = self.context_repository.fetch_code_neighborhood_batch(
            list(unique_start_ids),
            self.max_call_depth,
        )

        nodes_by_id: dict[str, dict[str, Any]] = {}
        for row in neighborhood_rows:
            node_id = str(row["id"])
            existing = nodes_by_id.get(node_id)
            if existing is None or int(row["depth"]) < int(existing.get("depth", 0)):
                nodes_by_id[node_id] = row

        sorted_nodes = sorted(
            nodes_by_id.values(),
            key=lambda row: (int(row.get("depth", 0)), str(row.get("file_path", ""))),
        )

        with self._cache_lock:
            if len(self._neighborhood_cache) >= self.neighborhood_cache_max_entries:
                self._neighborhood_cache.clear()
            self._neighborhood_cache[cache_key] = sorted_nodes

        return sorted_nodes

    def _build_context_nodes(self, rows: list[dict[str, Any]]) -> list[CodeContextNode]:
        """Convert Neo4j rows into context nodes with snippets.

        Args:
            rows: Neo4j rows for code nodes.

        Returns:
            List of context nodes with snippet content.
        """

        nodes: list[CodeContextNode] = []
        for row in rows:
            file_path = Path(str(row.get("file_path", "")))
            line_start = self._coerce_int(row.get("line_start"))
            line_end = self._coerce_int(row.get("line_end"))
            snippet = self._read_snippet(file_path, line_start, line_end)
            nodes.append(
                CodeContextNode(
                    node_id=str(row["id"]),
                    node_kind=self._coerce_str(row.get("node_kind")),
                    name=self._coerce_str(row.get("name")),
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    depth=int(row.get("depth", 0)),
                    snippet=snippet,
                )
            )

        return nodes

    def _render_context(self, nodes: list[CodeContextNode]) -> tuple[str, int]:
        """Render text context for a finding and enforce token budget.

        Args:
            nodes: Context nodes to render.

        Returns:
            Tuple of rendered context text and token count.
        """

        parts: list[str] = []
        total_tokens = 0

        for node in self._select_render_nodes(nodes):
            snippet = self._sanitize_snippet(node.snippet)
            if not self._starts_with_python_anchor(snippet):
                continue
            snippet_block = snippet
            if not snippet_block:
                _LOGGER.warning(
                    "Empty snippet for node %s in file %s",
                    node.node_id,
                    node.file_path,
                )
            candidate_text = "\n\n".join([*parts, snippet_block])
            candidate_tokens = self._estimate_tokens(candidate_text)
            if candidate_tokens > self.token_budget:
                break
            parts.append(snippet_block)
            total_tokens = candidate_tokens

        return "\n\n".join(parts), total_tokens

    def _select_render_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Select and prioritize nodes to produce complete-looking source snippets."""

        preferred_nodes = [
            node
            for node in nodes
            if self._is_preferred_render_node_kind(node.node_kind)
            and self._is_renderable_node(node)
        ]
        if preferred_nodes:
            candidate_nodes = preferred_nodes
        else:
            candidate_nodes = [node for node in nodes if self._is_renderable_node(node)]

        sorted_nodes = sorted(
            candidate_nodes,
            key=lambda node: (
                node.depth,
                -self._node_span(node),
                str(node.file_path),
                node.line_start or 0,
            ),
        )

        unique_nodes: list[CodeContextNode] = []
        seen_keys: set[tuple[str, int, int, str]] = set()
        for node in sorted_nodes:
            snippet = node.snippet.strip()
            key = (
                str(node.file_path),
                node.line_start or 0,
                node.line_end or 0,
                snippet,
            )
            if key in seen_keys:
                continue
            seen_keys.add(key)
            unique_nodes.append(node)

        return unique_nodes

    @staticmethod
    def _node_span(node: CodeContextNode) -> int:
        """Return line span for ordering nodes by snippet completeness."""

        if node.line_start is None or node.line_end is None:
            return 0
        return max(0, node.line_end - node.line_start)

    @staticmethod
    def _is_full_context_node_kind(node_kind: str | None) -> bool:
        """Return whether a node kind represents a complete source structure."""

        return node_kind in FULL_CONTEXT_NODE_KINDS

    @staticmethod
    def _is_preferred_render_node_kind(node_kind: str | None) -> bool:
        """Return whether node kind should be prioritized for final text rendering."""

        return node_kind in PREFERRED_RENDER_NODE_KINDS

    @staticmethod
    def _is_renderable_node(node: CodeContextNode) -> bool:
        """Return whether node snippet should be rendered into final context text."""

        snippet = node.snippet.strip()
        if not snippet:
            return False

        if not ContextAssemblerService._has_python_anchor(snippet):
            return False

        if ContextAssemblerService._has_dangling_snippet_end(snippet):
            return False

        return not (node.node_kind in PREFERRED_RENDER_NODE_KINDS and "\n" not in snippet)

    @staticmethod
    def _has_python_anchor(snippet: str) -> bool:
        """Return whether snippet contains a clear Python declaration/decorator anchor."""

        for line in snippet.splitlines():
            stripped = line.lstrip()
            if (
                stripped.startswith("@")
                or stripped.startswith("def ")
                or stripped.startswith("async def ")
                or stripped.startswith("class ")
            ):
                return True
        return False

    @staticmethod
    def _has_dangling_snippet_end(snippet: str) -> bool:
        """Return whether snippet appears to end at an obviously incomplete token."""

        stripped = snippet.rstrip()
        if not stripped:
            return True

        return stripped.endswith(("(", "[", "{", ",", "\\"))

    @staticmethod
    def _starts_with_python_anchor(snippet: str) -> bool:
        """Return whether snippet begins with a structural Python anchor line."""

        for line in snippet.splitlines():
            stripped = line.lstrip()
            if not stripped:
                continue
            return ContextAssemblerService._is_python_anchor_line(stripped)
        return False

    @staticmethod
    def _is_python_anchor_line(stripped_line: str) -> bool:
        """Return whether a stripped line starts with a Python structural anchor."""

        return (
            stripped_line.startswith("@")
            or stripped_line.startswith("def ")
            or stripped_line.startswith("async def ")
            or stripped_line.startswith("class ")
        )

    @staticmethod
    def _is_python_signature_line(stripped_line: str) -> bool:
        """Return whether a stripped line starts with a Python declaration signature."""

        return (
            stripped_line.startswith("def ")
            or stripped_line.startswith("async def ")
            or stripped_line.startswith("class ")
        )

    @staticmethod
    def _anchor_has_body(lines: list[str], anchor_index: int) -> bool:
        """Return whether the declaration line at anchor_index has body lines after it."""

        anchor_line = lines[anchor_index]
        anchor_indent = len(anchor_line) - len(anchor_line.lstrip())
        for following_line in lines[anchor_index + 1 :]:
            stripped = following_line.strip()
            if not stripped:
                continue
            following_indent = len(following_line) - len(following_line.lstrip())
            return following_indent > anchor_indent
        return False

    @staticmethod
    def _sanitize_snippet(snippet: str) -> str:
        """Trim snippet boundaries so text starts/ends at coherent Python anchors."""

        raw_lines = snippet.strip().splitlines()
        if not raw_lines:
            return ""

        lines = raw_lines
        for index, line in enumerate(raw_lines):
            stripped = line.lstrip()
            if ContextAssemblerService._is_python_anchor_line(stripped):
                lines = raw_lines[index:]
                break

        while lines and lines[-1].lstrip().startswith("@"):
            lines.pop()

        while lines and not lines[-1].strip():
            lines.pop()

        while lines:
            last_index = len(lines) - 1
            stripped_last = lines[last_index].lstrip()
            if not ContextAssemblerService._is_python_signature_line(stripped_last):
                break
            if ContextAssemblerService._anchor_has_body(lines, last_index):
                break

            lines.pop()
            while lines and lines[-1].lstrip().startswith("@"):
                lines.pop()
            while lines and not lines[-1].strip():
                lines.pop()

        return "\n".join(lines).strip()

    @staticmethod
    def sanitize_python_snippet(snippet: str) -> str:
        """Public sanitizer for Python-like snippet boundaries."""

        return ContextAssemblerService._sanitize_snippet(snippet)

    @staticmethod
    def starts_with_python_anchor(snippet: str) -> bool:
        """Public predicate for structural Python snippet starts."""

        return ContextAssemblerService._starts_with_python_anchor(snippet)

    def _read_snippet(self, file_path: Path, line_start: int | None, line_end: int | None) -> str:
        """Read a code snippet for the given file and line range.

        Args:
            file_path: Relative path of the source file.
            line_start: First line to include.
            line_end: Last line to include.

        Returns:
            Snippet text or an empty string when unavailable.
        """

        if line_start is None or line_end is None or line_start < 1 or line_end < line_start:
            return ""

        absolute_path = (self.project_root / file_path).resolve()
        if not absolute_path.exists():
            return ""

        snippet_key = (absolute_path, line_start, line_end)

        with self._cache_lock:
            cached_snippet = self._snippet_cache.get(snippet_key)
        if cached_snippet is not None:
            return cached_snippet

        with self._cache_lock:
            lines = self._file_lines_cache.get(absolute_path)

        if lines is None:
            with absolute_path.open("r", encoding="utf-8", errors="ignore") as handle:
                lines = handle.readlines()
            with self._cache_lock:
                self._file_lines_cache[absolute_path] = lines

        start_index = max(line_start - 1, 0)
        end_index = min(line_end, len(lines))
        snippet = "".join(lines[start_index:end_index]).rstrip()

        with self._cache_lock:
            if len(self._snippet_cache) >= self.snippet_cache_max_entries:
                self._snippet_cache.clear()
            self._snippet_cache[snippet_key] = snippet

        return snippet

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
        return max(1, int(len(text) * 0.25)) if text else 0

    def _finding_description(self, finding: FindingNode) -> str:
        """Build a short description for the finding.

        Args:
            finding: Finding node to describe.

        Returns:
            Short description string.
        """

        if isinstance(finding, BanditFindingNode):
            severity_label = finding.severity.value
            return f"cwe={finding.cwe_id} severity={severity_label}"
        if isinstance(finding, DlintFindingNode):
            return f"issue_id={finding.issue_id}"
        return ""

    @staticmethod
    def _coerce_str(value: Any | None) -> str | None:
        """Convert a value to string when possible."""

        if value is None:
            return None
        return str(value)

    @staticmethod
    def _coerce_int(value: Any | None) -> int | None:
        """Convert a value to int when possible."""

        if value is None:
            return None
        return int(value)
