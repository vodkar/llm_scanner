from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from models.bandit_report import IssueSeverity
from models.context import CodeContextNode, ContextAssembly, FindingContext
from models.nodes.finding import BanditFindingNode, DlintFindingNode, FindingNode
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.context import ContextRepository

TokenEstimator = Callable[[str], int]


class ContextAssemblerService(BaseModel):
    """Assemble LLM context for vulnerability findings."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path
    bandit_repository: BanditFindingsRepository
    dlint_repository: DlintFindingsRepository
    context_repository: ContextRepository
    max_call_depth: int = 3
    token_budget: int = 2048
    token_estimator: TokenEstimator | None = None

    def assemble(self) -> ContextAssembly:
        """Build context objects for all analyzer findings.

        Returns:
            Context assembly with one entry per finding.
        """

        findings: list[FindingNode] = []
        findings.extend(self.bandit_repository.iter_findings_for_project(self.project_root))
        findings.extend(self.dlint_repository.iter_findings_for_project(self.project_root))

        if not findings:
            return ContextAssembly()

        finding_ids: list[str] = [str(finding.identifier) for finding in findings]
        reported_rows = self.context_repository.fetch_reported_code_nodes(finding_ids)

        finding_to_nodes: dict[str, list[dict[str, object]]] = defaultdict(list)
        for row in reported_rows:
            finding_to_nodes[str(row["finding_id"])].append(row)

        contexts: list[FindingContext] = []
        for finding in findings:
            finding_id = str(finding.identifier)
            reported_nodes = finding_to_nodes.get(finding_id, [])
            contexts.append(
                self._assemble_finding_context(
                    finding=finding,
                    reported_nodes=reported_nodes,
                )
            )

        return ContextAssembly(findings=contexts)

    def _assemble_finding_context(
        self,
        *,
        finding: FindingNode,
        reported_nodes: list[dict[str, object]],
    ) -> FindingContext:
        """Assemble context for a single finding.

        Args:
            finding: Finding node produced by analyzers.
            reported_nodes: Neo4j rows for nodes directly reported by the finding.

        Returns:
            Finding context with nodes and text.
        """

        start_node_ids: list[str] = [
            str(row["code_id"]) for row in reported_nodes if row.get("code_id")
        ]
        neighborhood_rows = self._expand_neighborhood(start_node_ids)

        nodes = self._build_context_nodes(neighborhood_rows)
        context_text, token_count = self._render_context(finding, nodes)

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

    def _expand_neighborhood(self, start_node_ids: list[str]) -> list[dict[str, Any]]:
        """Expand code nodes with BFS traversal across code relationships.

        Args:
            start_node_ids: List of code node identifiers.

        Returns:
            Unique code node rows ordered by traversal depth.
        """

        if not start_node_ids:
            return []

        nodes_by_id: dict[str, dict[str, Any]] = {}
        for start_id in start_node_ids:
            rows = self.context_repository.fetch_code_neighborhood(start_id, self.max_call_depth)
            for row in rows:
                node_id = str(row["id"])
                existing = nodes_by_id.get(node_id)
                if existing is None or int(row["depth"]) < int(existing.get("depth", 0)):
                    nodes_by_id[node_id] = row

        return sorted(
            nodes_by_id.values(),
            key=lambda row: (int(row.get("depth", 0)), str(row.get("file_path", ""))),
        )

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

    def _render_context(
        self, finding: FindingNode, nodes: list[CodeContextNode]
    ) -> tuple[str, int]:
        """Render text context for a finding and enforce token budget.

        Args:
            finding: Finding node metadata.
            nodes: Context nodes to render.

        Returns:
            Tuple of rendered context text and token count.
        """

        parts: list[str] = [
            f"Finding: {finding.__class__.__name__} {self._finding_description(finding)}",
            f"Location: {finding.file}:{finding.line_number}",
        ]
        total_tokens = self._estimate_tokens("\n".join(parts))

        for node in nodes:
            header = (
                f"Node: {node.node_kind or 'Code'} {node.name or ''} "
                f"{node.file_path}:{node.line_start}-{node.line_end}"
            ).strip()
            snippet_block = node.snippet.strip()
            node_text = f"{header}\n{snippet_block}" if snippet_block else header
            candidate_text = "\n\n".join(parts + [node_text])
            candidate_tokens = self._estimate_tokens(candidate_text)
            if candidate_tokens > self.token_budget:
                break
            parts.append(node_text)
            total_tokens = candidate_tokens

        return "\n\n".join(parts), total_tokens

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

        with absolute_path.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()

        start_index = max(line_start - 1, 0)
        end_index = min(line_end, len(lines))
        return "".join(lines[start_index:end_index]).rstrip()

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
            severity = finding.severity
            severity_label = (
                severity.value if isinstance(severity, IssueSeverity) else str(severity)
            )
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
