import logging
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, PrivateAttr

from models.base import NodeID
from models.context import CodeContextNode, Context, ContextAssembly, FileSpans
from models.nodes.finding import BanditFindingNode, DlintFindingNode, FindingNode
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.context import ContextRepository

TokenEstimator = Callable[[str], int]
_LOGGER = logging.getLogger(__name__)
LOGGING_INTERVAL = 200
FULL_CONTEXT_NODE_KINDS: tuple[str, ...] = ("FunctionNode", "ClassNode", "CodeBlockNode")
PREFERRED_RENDER_NODE_KINDS: tuple[str, ...] = (
    "FunctionNode",
    "ClassNode",
    "VariableNode",
    "CodeBlockNode",
)


class ContextAssemblerService(BaseModel):
    """Assemble LLM context for vulnerability findings."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path
    bandit_repository: BanditFindingsRepository
    dlint_repository: DlintFindingsRepository
    context_repository: ContextRepository
    max_call_depth: int
    token_budget: int
    context_workers: int = 30
    snippet_cache_max_entries: int = 10000
    token_estimator: TokenEstimator | None = None

    _cache_lock: Lock = PrivateAttr(default_factory=Lock)
    _file_lines_cache: dict[Path, list[str]] = PrivateAttr(
        default_factory=lambda: cast(dict[Path, list[str]], {})
    )
    _snippet_cache: dict[tuple[Path, int, int], str] = PrivateAttr(
        default_factory=lambda: cast(dict[tuple[Path, int, int], str], {})
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
        return ContextAssembly(contexts=contexts)

    def assemble_for_spans(self, repo_path: Path, files_spans: list[FileSpans]) -> Context:
        """Assemble context for findings overlapping specific file and line spans."""

        _LOGGER.info(
            "Assembling context for %d file spans in repository: %s", len(files_spans), repo_path
        )

        for file_span in files_spans:
            if any(start < 1 for start, _ in file_span.line_spans):
                raise ValueError("start_line must be >= 1")
            if any(end < start for start, end in file_span.line_spans):
                raise ValueError("end_line must be >= start_line")

        spans_nodes = self.context_repository.fetch_code_nodes_by_file_lines(
            [
                {
                    "file_path": str(file_span.file_path),
                    "line_number": line_number,
                }
                for file_span in files_spans
                for line_span in file_span.line_spans
                for line_number in range(line_span[0], line_span[1] + 1)
            ]
        )
        context_nodes = self.context_repository.fetch_code_neighborhood_batch(
            [node.node_id for node in spans_nodes],
            self.max_call_depth,
        )

        context_text, token_count = self._render_context(repo_path, context_nodes)

        return Context(
            description="Finding from spans query",
            context_text=context_text,
            token_count=token_count,
        )

    def assemble_for_vulnerability_span(
        self,
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
            tuple[FindingNode, list[CodeContextNode], list[CodeContextNode]]
        ] = []
        non_associated_inputs: list[
            tuple[FindingNode, list[CodeContextNode], list[CodeContextNode]]
        ] = []

        for finding in findings:
            _, reported_nodes, enclosing_nodes = self._finding_input(
                finding=finding,
                finding_to_nodes=finding_to_nodes,
                line_to_enclosing_nodes=line_to_enclosing_nodes,
            )
            if self._finding_overlaps_span(
                reported_nodes=reported_nodes,
                enclosing_nodes=enclosing_nodes,
                target_file=target_file,
                start_line=start_line,
                end_line=end_line,
            ):
                associated_inputs.append((finding, reported_nodes, enclosing_nodes))
            else:
                non_associated_inputs.append((finding, reported_nodes, enclosing_nodes))

        associated_contexts = self._assemble_finding_inputs(associated_inputs)
        limited_non_associated = non_associated_inputs[: max(0, non_associated_limit)]
        non_associated_contexts = self._assemble_finding_inputs(limited_non_associated)

        return ContextAssembly(contexts=associated_contexts), ContextAssembly(
            contexts=non_associated_contexts
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
        dict[str, list[CodeContextNode]],
        dict[tuple[str, int], list[CodeContextNode]],
    ]:
        """Load and index row data required to assemble finding contexts."""

        enclosing_nodes = self.context_repository.fetch_code_nodes_by_file_lines(
            [
                {
                    "file_path": str(finding.file),
                    "line_number": finding.line_number,
                }
                for finding in findings
            ]
        )

        finding_to_nodes: dict[str, list[CodeContextNode]] = {
            str(finding.identifier): self.context_repository.fetch_reported_code_nodes(
                str(finding.identifier)
            )
            for finding in findings
        }

        nodes_by_file: dict[str, list[CodeContextNode]] = defaultdict(list)
        for node in enclosing_nodes:
            nodes_by_file[str(node.file_path)].append(node)

        line_to_enclosing_nodes: dict[tuple[str, int], list[CodeContextNode]] = defaultdict(list)
        for finding in findings:
            file_path = str(finding.file)
            for node in nodes_by_file.get(file_path, []):
                if node.line_start <= finding.line_number <= node.line_end:
                    line_to_enclosing_nodes[(file_path, finding.line_number)].append(node)

        return finding_to_nodes, line_to_enclosing_nodes

    def _finding_input(
        self,
        finding: FindingNode,
        finding_to_nodes: dict[str, list[CodeContextNode]],
        line_to_enclosing_nodes: dict[tuple[str, int], list[CodeContextNode]],
    ) -> tuple[FindingNode, list[CodeContextNode], list[CodeContextNode]]:
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
        finding_inputs: list[tuple[FindingNode, list[CodeContextNode], list[CodeContextNode]]],
    ) -> list[Context]:
        """Assemble contexts for precomputed finding input tuples."""

        if not finding_inputs:
            return []

        def _assemble_item(
            finding_input: tuple[FindingNode, list[CodeContextNode], list[CodeContextNode]],
        ) -> Context:
            finding, reported_nodes, enclosing_nodes = finding_input
            return self._assemble_finding_context(
                finding=finding,
                reported_nodes=reported_nodes,
                enclosing_nodes=enclosing_nodes,
            )

        contexts: list[Context] = []
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
        reported_nodes: list[CodeContextNode],
        enclosing_nodes: list[CodeContextNode],
        target_file: Path,
        start_line: int,
        end_line: int,
    ) -> bool:
        """Check whether a finding's code node range overlaps a target span."""

        node_spans = self._finding_node_spans(
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
        reported_nodes: list[CodeContextNode],
        enclosing_nodes: list[CodeContextNode],
    ) -> list[tuple[Path, int, int]]:
        """Return candidate node spans for a finding using reported rows and fallback."""

        spans: list[tuple[Path, int, int]] = []
        for node in reported_nodes:
            if node.line_end < node.line_start:
                continue
            spans.append((node.file_path, node.line_start, node.line_end))

        if spans:
            return spans

        for node in enclosing_nodes:
            if node.line_end < node.line_start:
                continue
            spans.append((node.file_path, node.line_start, node.line_end))

        return spans

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
        reported_nodes: list[CodeContextNode],
        enclosing_nodes: list[CodeContextNode],
    ) -> Context:
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
        nodes = self.context_repository.fetch_code_neighborhood_batch(
            start_node_ids,
            self.max_call_depth,
        )
        context_text, token_count = self._render_context(self.project_root, nodes)

        return Context(
            description=self._finding_description(finding),
            context_text=context_text,
            token_count=token_count,
        )

    def _resolve_start_node_ids(
        self,
        reported_nodes: list[CodeContextNode],
        enclosing_nodes: list[CodeContextNode],
    ) -> list[str]:
        """Resolve traversal start node IDs for a finding.

        Args:
            reported_nodes: Nodes directly linked by ``REPORTS``.
            enclosing_nodes: Nodes containing the finding file/line pair.

        Returns:
            Unique start node IDs, including promoted full-node IDs when available.
        """

        start_node_ids: set[str] = {node.node_id for node in reported_nodes}

        promoted_id = self._select_full_context_node_id(enclosing_nodes)
        if promoted_id is not None:
            start_node_ids.add(promoted_id)

        return sorted(start_node_ids)

    def _select_full_context_node_id(self, rows: list[CodeContextNode]) -> str | None:
        """Pick the best enclosing code node for full snippet context."""

        best_id: str | None = None
        best_rank: tuple[int, int] | None = None

        for node in rows:
            if node.line_end < node.line_start:
                continue

            span = node.line_end - node.line_start
            is_preferred_kind = int(node.node_kind in FULL_CONTEXT_NODE_KINDS)
            rank = (is_preferred_kind, span)

            if best_rank is None or rank > best_rank:
                best_rank = rank
                best_id = node.node_id

        return best_id

    def _render_context(self, repo_path: Path, nodes: list[CodeContextNode]) -> tuple[str, int]:
        """Render text context for a finding and enforce token budget.

        Args:
            repo_path: Path to the repository root.
            nodes: Context nodes to render.

        Returns:
            Tuple of rendered context text, token count, and context nodes.
        """
        _LOGGER.debug("Rendering context for %d nodes", len(nodes))

        # Zero pass, sorting and prioritization
        nodes = self._select_render_nodes(nodes)

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

    @staticmethod
    def _sanitize_snippet(snippet: str) -> str:
        """Trim snippet boundaries so text starts/ends at coherent Python anchors."""

        raw_lines = snippet.strip().splitlines()
        if not raw_lines:
            return ""

        return "\n".join(
            line for line in raw_lines if line.strip() and not line.strip().startswith("#")
        )

    def _select_render_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """
        Select and prioritize nodes to produce complete-looking source snippets.
        This removes duplicate nodes and promotes nodes of preferred kinds.
        Prioritization is based on node kind, depth, and repetition.
        """

        candidate_nodes: dict[NodeID, CodeContextNode] = {}
        for node in nodes:
            if self._is_preferred_render_node_kind(node.node_kind):
                if node.node_id in candidate_nodes:
                    candidate_nodes[node.node_id].repeats += 1
                    candidate_nodes[node.node_id].depth = min(
                        candidate_nodes[node.node_id].depth, node.depth
                    )
                else:
                    candidate_nodes[node.node_id] = node

        return sorted(
            candidate_nodes.values(),
            key=lambda node: (
                node.depth,
                node.repeats,
            ),
        )

    @staticmethod
    def _is_preferred_render_node_kind(node_kind: str | None) -> bool:
        """Return whether node kind should be prioritized for final text rendering."""

        return node_kind in PREFERRED_RENDER_NODE_KINDS

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
