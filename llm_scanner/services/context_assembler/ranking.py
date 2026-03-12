from __future__ import annotations

from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Final, cast

from pydantic import BaseModel, ConfigDict

from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.context import CodeContextNode
from models.edges.base import RelationshipBase
from models.edges.call_graph import CallGraphCalledBy, CallGraphCalls
from models.edges.control_flow import ControlFlowContains
from models.nodes import Node
from models.nodes.base import BaseCodeNode
from models.nodes.finding import BanditFindingNode, DlintFindingNode, FindingNode

SnippetReader = Callable[[Path, int | None, int | None], str]

GRAPH_ROLE_WEIGHT: Final[float] = 0.30
FINDING_EVIDENCE_WEIGHT: Final[float] = 0.25
SECURITY_PATH_WEIGHT: Final[float] = 0.25
STRUCTURE_WEIGHT: Final[float] = 0.10
FILE_PRIOR_WEIGHT: Final[float] = 0.10

RELATION_CLASS_WEIGHTS: Final[dict[str, float]] = {
    "directly_reported_node": 1.00,
    "best_enclosing_node": 0.95,
    "direct_caller": 0.85,
    "direct_callee": 0.80,
    "parent_block_or_class": 0.70,
    "child_block": 0.60,
    "same-file sibling": 0.35,
    "cross-file neighbor": 0.20,
    "weak analysis-only link": 0.10,
}
HOP_DECAY_BY_DEPTH: Final[dict[int, float]] = {
    0: 1.00,
    1: 0.90,
    2: 0.75,
    3: 0.55,
    4: 0.35,
}
SEVERITY_SCORES: Final[dict[IssueSeverity, float]] = {
    IssueSeverity.LOW: 0.33,
    IssueSeverity.MEDIUM: 0.66,
    IssueSeverity.HIGH: 1.00,
}
RENDER_KIND_SCORES: Final[dict[str, float]] = {
    "FunctionNode": 1.00,
    "ClassNode": 0.80,
    "CodeBlockNode": 0.70,
    "VariableNode": 0.40,
}
FULL_CONTEXT_NODE_KINDS: Final[tuple[str, ...]] = (
    "FunctionNode",
    "ClassNode",
    "CodeBlockNode",
)
HELPER_HINTS: Final[tuple[str, ...]] = ("helper", "wrapper", "util", "utils", "common")
SINK_HINTS: Final[tuple[str, ...]] = (
    "subprocess",
    "os.system",
    "popen",
    "eval",
    "exec",
    "pickle.loads",
    "yaml.load",
    "render_template",
    "execute",
)
SOURCE_HINTS: Final[tuple[str, ...]] = (
    "request",
    "argv",
    "sys.argv",
    "getenv",
    "environ",
    "input",
    "headers",
    "cookies",
    "body",
)
GUARD_HINTS: Final[tuple[str, ...]] = (
    "validate",
    "sanitize",
    "escape",
    "normalize",
    "check",
    "authorize",
    "allow",
    "deny",
    "guard",
    "safe",
)
GENERATED_FILE_SUFFIXES: Final[tuple[str, ...]] = ("_pb2.py",)
GENERATED_PATH_MARKERS: Final[tuple[str, ...]] = (
    "generated",
    "autogen",
    "auto_generated",
)
GENERATED_HEADER_MARKERS: Final[tuple[str, ...]] = (
    "generated",
    "auto-generated",
    "do not edit",
)


class NodeRelevanceRankingService(BaseModel):
    """Rank code nodes for context assembly using Phase 1 heuristics."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path | None = None
    snippet_reader: SnippetReader | None = None

    def rank_nodes(
        self,
        nodes: dict[NodeID, Node],
        edges: list[RelationshipBase],
        bandit_findings: list[BanditFindingNode],
        dlint_findings: list[DlintFindingNode],
    ) -> list[Node]:
        """Rank graph nodes by deterministic Phase 1 relevance."""

        all_findings: list[FindingNode] = [*bandit_findings, *dlint_findings]
        if not nodes:
            return []

        findings_by_node_id = self._match_findings_to_graph_nodes(
            nodes=nodes,
            findings=all_findings,
        )
        reported_node_ids = {node_id for node_id, matches in findings_by_node_id.items() if matches}
        promoted_node_ids = self._select_best_enclosing_graph_nodes(
            nodes=nodes,
            findings=all_findings,
        )
        seed_node_ids = reported_node_ids | promoted_node_ids
        adjacency = self._build_adjacency(edges)
        distances = self._compute_distances(seed_node_ids, adjacency)
        relation_classes = self._resolve_relation_classes(
            nodes=nodes,
            edges=edges,
            finding_files={finding.file for finding in all_findings},
            reported_node_ids=reported_node_ids,
            promoted_node_ids=promoted_node_ids,
            connected_node_ids=set(distances),
        )
        forced_keep_node_ids = set(seed_node_ids)
        helper_neighbor_id = self._select_helper_neighbor(
            nodes=nodes,
            edges=edges,
            helper_node_ids={
                node_id
                for node_id in seed_node_ids
                if self._looks_like_helper(
                    name=self._node_name(nodes[node_id]),
                    snippet=self._read_node_snippet(nodes[node_id]),
                )
            },
        )
        if helper_neighbor_id is not None:
            forced_keep_node_ids.add(helper_neighbor_id)

        scored_nodes: list[tuple[Node, float, bool, int]] = []
        for node_id, node in nodes.items():
            depth = distances.get(node_id, 0 if node_id in seed_node_ids else 99)
            score = self._score_node(
                node_kind=self._node_kind(node),
                file_path=self._node_file_path(node),
                depth=depth,
                repeats=0,
                relation_class=relation_classes.get(node_id, "weak analysis-only link"),
                direct_findings=findings_by_node_id.get(node_id, []),
                snippet=self._read_node_snippet(node),
                is_best_enclosing=node_id in promoted_node_ids,
                is_other_enclosing=node_id in reported_node_ids | promoted_node_ids,
                finding_files={finding.file for finding in all_findings},
            )
            updated_node = self._update_graph_node_score(node=node, new_score=score)
            scored_nodes.append((updated_node, score, node_id in forced_keep_node_ids, depth))

        scored_nodes.sort(
            key=lambda item: (
                not item[2],
                -item[1],
                item[3],
                str(self._node_file_path(item[0]) or ""),
                self._node_line_start(item[0]),
            )
        )
        return [node for node, _score, _forced_keep, _depth in scored_nodes]

    def rank_context_nodes(
        self,
        *,
        nodes: list[CodeContextNode],
        reported_nodes: list[CodeContextNode],
        enclosing_nodes: list[CodeContextNode],
        finding: FindingNode,
    ) -> list[CodeContextNode]:
        """Rank context nodes before rendering for a single finding."""

        if not nodes:
            return []

        reported_node_ids: set[NodeID] = {node.node_id for node in reported_nodes}
        promoted_node_id = self._select_best_enclosing_context_node(enclosing_nodes)
        seed_node_ids: set[NodeID] = set(reported_node_ids)
        if promoted_node_id is not None:
            seed_node_ids.add(promoted_node_id)

        best_helper_neighbor_id = self._select_best_context_helper_neighbor(
            nodes=nodes,
            seed_node_ids=seed_node_ids,
        )

        scored_nodes: list[tuple[CodeContextNode, bool]] = []
        for node in nodes:
            relation_class = self._resolve_context_relation_class(
                node=node,
                finding=finding,
                reported_node_ids=reported_node_ids,
                promoted_node_id=promoted_node_id,
            )
            direct_findings = [finding] if node.node_id in reported_node_ids else []
            score = self._score_node(
                node_kind=node.node_kind,
                file_path=node.file_path,
                depth=node.depth,
                repeats=node.repeats,
                relation_class=relation_class,
                direct_findings=direct_findings,
                snippet=self._read_context_snippet(node),
                is_best_enclosing=node.node_id == promoted_node_id,
                is_other_enclosing=node.node_id
                in {candidate.node_id for candidate in enclosing_nodes},
                finding_files={finding.file},
            )
            forced_keep = node.node_id in seed_node_ids
            if best_helper_neighbor_id is not None and node.node_id == best_helper_neighbor_id:
                forced_keep = True
            scored_nodes.append((node.model_copy(update={"score": score}), forced_keep))

        scored_nodes.sort(
            key=lambda item: (
                not item[1],
                -item[0].score,
                item[0].depth,
                str(item[0].file_path),
                item[0].line_start,
            )
        )
        return [node for node, _forced_keep in scored_nodes]

    def _match_findings_to_graph_nodes(
        self,
        *,
        nodes: dict[NodeID, Node],
        findings: list[FindingNode],
    ) -> dict[NodeID, list[FindingNode]]:
        """Attach findings to graph nodes by file and line containment."""

        findings_by_node_id: dict[NodeID, list[FindingNode]] = {node_id: [] for node_id in nodes}
        for node_id, node in nodes.items():
            file_path = self._node_file_path(node)
            line_start = self._node_line_start(node)
            line_end = self._node_line_end(node)
            if file_path is None or line_start is None or line_end is None:
                continue
            for finding in findings:
                if (
                    self._paths_match(file_path, finding.file)
                    and line_start <= finding.line_number <= line_end
                ):
                    findings_by_node_id[node_id].append(finding)
        return findings_by_node_id

    def _select_best_enclosing_graph_nodes(
        self,
        *,
        nodes: dict[NodeID, Node],
        findings: list[FindingNode],
    ) -> set[NodeID]:
        """Choose the best enclosing graph node for each finding."""

        promoted_node_ids: set[NodeID] = set()
        for finding in findings:
            best_node_id: NodeID | None = None
            best_rank: tuple[int, int] | None = None
            for node_id, node in nodes.items():
                file_path = self._node_file_path(node)
                line_start = self._node_line_start(node)
                line_end = self._node_line_end(node)
                if file_path is None or line_start is None or line_end is None:
                    continue
                if not self._paths_match(file_path, finding.file):
                    continue
                if not line_start <= finding.line_number <= line_end:
                    continue
                rank = self._enclosing_rank(self._node_kind(node), line_start, line_end)
                if best_rank is None or rank > best_rank:
                    best_rank = rank
                    best_node_id = node_id
            if best_node_id is not None:
                promoted_node_ids.add(best_node_id)
        return promoted_node_ids

    def _build_adjacency(self, edges: list[RelationshipBase]) -> dict[NodeID, set[NodeID]]:
        """Build an undirected adjacency index from graph edges."""

        adjacency: dict[NodeID, set[NodeID]] = {}
        for edge in edges:
            adjacency.setdefault(edge.src, set()).add(edge.dst)
            adjacency.setdefault(edge.dst, set()).add(edge.src)
        return adjacency

    def _compute_distances(
        self,
        seed_node_ids: set[NodeID],
        adjacency: dict[NodeID, set[NodeID]],
    ) -> dict[NodeID, int]:
        """Compute unweighted graph distance from any seed node."""

        if not seed_node_ids:
            return {}

        distances: dict[NodeID, int] = {node_id: 0 for node_id in seed_node_ids}
        queue: deque[NodeID] = deque(seed_node_ids)
        while queue:
            current = queue.popleft()
            for neighbor in adjacency.get(current, set()):
                if neighbor in distances:
                    continue
                distances[neighbor] = distances[current] + 1
                queue.append(neighbor)
        return distances

    def _resolve_relation_classes(
        self,
        *,
        nodes: dict[NodeID, Node],
        edges: list[RelationshipBase],
        finding_files: set[Path],
        reported_node_ids: set[NodeID],
        promoted_node_ids: set[NodeID],
        connected_node_ids: set[NodeID],
    ) -> dict[NodeID, str]:
        """Resolve the strongest known relation class for each graph node."""

        seed_node_ids = reported_node_ids | promoted_node_ids
        relation_classes: dict[NodeID, str] = {}
        for node_id, node in nodes.items():
            if node_id in reported_node_ids:
                relation_classes[node_id] = "directly_reported_node"
                continue
            if node_id in promoted_node_ids:
                relation_classes[node_id] = "best_enclosing_node"
                continue

            relation_class = self._relation_class_from_edges(
                node_id=node_id, seed_node_ids=seed_node_ids, edges=edges
            )
            if relation_class is not None:
                relation_classes[node_id] = relation_class
                continue

            file_path = self._node_file_path(node)
            if file_path is not None and any(
                self._paths_match(file_path, finding_file) for finding_file in finding_files
            ):
                relation_classes[node_id] = "same-file sibling"
            elif node_id in connected_node_ids:
                relation_classes[node_id] = "cross-file neighbor"
            else:
                relation_classes[node_id] = "weak analysis-only link"

        return relation_classes

    def _relation_class_from_edges(
        self,
        *,
        node_id: NodeID,
        seed_node_ids: set[NodeID],
        edges: list[RelationshipBase],
    ) -> str | None:
        """Classify a graph node using direct structural edges to seed nodes."""

        for edge in edges:
            if isinstance(edge, (CallGraphCalls, CallGraphCalledBy)):
                if edge.src == node_id and edge.dst in seed_node_ids:
                    return "direct_caller"
                if edge.src in seed_node_ids and edge.dst == node_id:
                    return "direct_callee"
            if isinstance(edge, ControlFlowContains):
                if edge.src == node_id and edge.dst in seed_node_ids:
                    return "parent_block_or_class"
                if edge.src in seed_node_ids and edge.dst == node_id:
                    return "child_block"
        return None

    def _select_helper_neighbor(
        self,
        *,
        nodes: dict[NodeID, Node],
        edges: list[RelationshipBase],
        helper_node_ids: set[NodeID],
    ) -> NodeID | None:
        """Select one adjacent caller or callee when the seed looks like a helper."""

        best_candidate: tuple[int, NodeID] | None = None
        for edge in edges:
            if not isinstance(edge, (CallGraphCalls, CallGraphCalledBy)):
                continue
            if (
                edge.src in helper_node_ids
                and edge.dst in nodes
                and edge.dst not in helper_node_ids
            ):
                candidate = (0, edge.dst)
            elif (
                edge.dst in helper_node_ids
                and edge.src in nodes
                and edge.src not in helper_node_ids
            ):
                candidate = (0, edge.src)
            else:
                continue
            if best_candidate is None or candidate < best_candidate:
                best_candidate = candidate
        return None if best_candidate is None else best_candidate[1]

    def _select_best_enclosing_context_node(
        self,
        rows: list[CodeContextNode],
    ) -> NodeID | None:
        """Pick the best enclosing code node for full snippet context."""

        best_node_id: NodeID | None = None
        best_rank: tuple[int, int] | None = None
        for node in rows:
            if node.line_end < node.line_start:
                continue
            rank = self._enclosing_rank(node.node_kind, node.line_start, node.line_end)
            if best_rank is None or rank > best_rank:
                best_rank = rank
                best_node_id = node.node_id
        return best_node_id

    def _select_best_context_helper_neighbor(
        self,
        *,
        nodes: list[CodeContextNode],
        seed_node_ids: set[NodeID],
    ) -> NodeID | None:
        """Choose a same-file near neighbor when the direct seed looks helper-like."""

        seed_nodes = [node for node in nodes if node.node_id in seed_node_ids]
        if not any(
            self._looks_like_helper(name=node.name, snippet=self._read_context_snippet(node))
            for node in seed_nodes
        ):
            return None

        best_candidate: tuple[int, int, NodeID] | None = None
        for node in nodes:
            if node.node_id in seed_node_ids:
                continue
            candidate_rank = (
                node.depth,
                -(node.line_end - node.line_start),
                node.node_id,
            )
            if best_candidate is None or candidate_rank < best_candidate:
                best_candidate = candidate_rank
        return None if best_candidate is None else best_candidate[2]

    def _resolve_context_relation_class(
        self,
        *,
        node: CodeContextNode,
        finding: FindingNode,
        reported_node_ids: set[NodeID],
        promoted_node_id: NodeID | None,
    ) -> str:
        """Resolve the strongest known relation class for a context node."""

        if node.node_id in reported_node_ids:
            return "directly_reported_node"
        if promoted_node_id is not None and node.node_id == promoted_node_id:
            return "best_enclosing_node"
        if self._paths_match(node.file_path, finding.file):
            return "same-file sibling"
        return "cross-file neighbor"

    def _score_node(
        self,
        *,
        node_kind: str | None,
        file_path: Path | None,
        depth: int,
        repeats: int,
        relation_class: str,
        direct_findings: list[FindingNode],
        snippet: str,
        is_best_enclosing: bool,
        is_other_enclosing: bool,
        finding_files: set[Path],
    ) -> float:
        """Compute the Phase 1 score for one node."""

        graph_role_score = RELATION_CLASS_WEIGHTS.get(relation_class, 0.10) * self._hop_decay(depth)
        node_finding_evidence_score = self._node_finding_evidence_score(direct_findings)
        security_path_score = self._security_path_score(
            snippet=snippet, direct_findings=direct_findings
        )
        structure_score = self._structure_score(
            node_kind=node_kind,
            repeats=repeats,
            is_best_enclosing=is_best_enclosing,
            is_other_enclosing=is_other_enclosing,
        )
        file_prior_score = self._file_prior_score(
            file_path=file_path, finding_files=finding_files, snippet=snippet
        )

        final_score = (
            GRAPH_ROLE_WEIGHT * graph_role_score
            + FINDING_EVIDENCE_WEIGHT * node_finding_evidence_score
            + SECURITY_PATH_WEIGHT * security_path_score
            + STRUCTURE_WEIGHT * structure_score
            + FILE_PRIOR_WEIGHT * file_prior_score
        )
        return max(0.0, min(1.0, round(final_score, 6)))

    def _hop_decay(self, depth: int) -> float:
        """Return the configured hop decay for traversal depth."""

        if depth in HOP_DECAY_BY_DEPTH:
            return HOP_DECAY_BY_DEPTH[depth]
        return 0.20

    def _node_finding_evidence_score(self, direct_findings: list[FindingNode]) -> float:
        """Score direct analyzer evidence attached to a node."""

        if not direct_findings:
            return 0.0

        severity_score = max(
            (SEVERITY_SCORES[finding.severity] if isinstance(finding, BanditFindingNode) else 0.50)
            for finding in direct_findings
        )
        confidence_score = 0.50
        has_bandit = any(isinstance(finding, BanditFindingNode) for finding in direct_findings)
        has_dlint = any(isinstance(finding, DlintFindingNode) for finding in direct_findings)
        if has_bandit and has_dlint:
            agreement_score = 1.00
        elif len(direct_findings) > 1:
            agreement_score = 0.30
        else:
            agreement_score = 0.00
        return 0.50 * severity_score + 0.30 * confidence_score + 0.20 * agreement_score

    def _security_path_score(self, *, snippet: str, direct_findings: list[FindingNode]) -> float:
        """Score sink, source, guard, and explicit path evidence heuristics."""

        normalized_text = snippet.lower()
        sink_indicator = 1.0 if any(hint in normalized_text for hint in SINK_HINTS) else 0.0
        source_indicator = 1.0 if any(hint in normalized_text for hint in SOURCE_HINTS) else 0.0
        guard_indicator = 1.0 if any(hint in normalized_text for hint in GUARD_HINTS) else 0.0
        security_path_evidence = 0.0
        if any(
            isinstance(finding, BanditFindingNode) and finding.cwe_id in {78, 79, 89, 502}
            for finding in direct_findings
        ):
            security_path_evidence = max(sink_indicator, 0.70)
        return (
            0.35 * sink_indicator
            + 0.25 * source_indicator
            + 0.20 * guard_indicator
            + 0.20 * security_path_evidence
        )

    def _structure_score(
        self,
        *,
        node_kind: str | None,
        repeats: int,
        is_best_enclosing: bool,
        is_other_enclosing: bool,
    ) -> float:
        """Score node structure for final rendering usefulness."""

        if is_best_enclosing:
            enclosing_bonus = 1.00
        elif is_other_enclosing:
            enclosing_bonus = 0.60
        else:
            enclosing_bonus = 0.00

        if repeats <= 0:
            repeat_bonus = 0.00
        elif repeats == 1:
            repeat_bonus = 0.40
        elif repeats == 2:
            repeat_bonus = 0.70
        else:
            repeat_bonus = 1.00

        render_kind_bonus = RENDER_KIND_SCORES.get(node_kind or "", 0.20)
        return 0.50 * enclosing_bonus + 0.30 * repeat_bonus + 0.20 * render_kind_bonus

    def _file_prior_score(
        self, *, file_path: Path | None, finding_files: set[Path], snippet: str
    ) -> float:
        """Score locality and generated-file priors."""

        if file_path is None:
            return 0.0

        same_file_bonus = (
            1.00
            if any(self._paths_match(file_path, finding_file) for finding_file in finding_files)
            else 0.00
        )
        same_module_bonus = max(
            (self._same_module_bonus(file_path, finding_file) for finding_file in finding_files),
            default=0.00,
        )
        generated_penalty = (
            1.00 if self._is_generated_file(file_path=file_path, snippet=snippet) else 0.00
        )
        return max(
            0.0,
            0.70 * same_file_bonus + 0.20 * same_module_bonus - 0.10 * generated_penalty,
        )

    def _same_module_bonus(self, file_path: Path, finding_file: Path) -> float:
        """Approximate whether two files belong to the same module or package."""

        file_parts = self._path_parts(file_path)
        finding_parts = self._path_parts(finding_file)
        if not file_parts or not finding_parts:
            return 0.0
        if file_parts[:-1] == finding_parts[:-1]:
            return 1.0
        common_prefix = 0
        for file_part, finding_part in zip(file_parts[:-1], finding_parts[:-1], strict=False):
            if file_part != finding_part:
                break
            common_prefix += 1
        return 0.50 if common_prefix > 0 else 0.00

    def _is_generated_file(self, *, file_path: Path, snippet: str) -> bool:
        """Return whether generated-file markers are confidently present."""

        normalized_path = file_path.as_posix().lower()
        if any(normalized_path.endswith(suffix) for suffix in GENERATED_FILE_SUFFIXES):
            return True
        if any(marker in normalized_path.split("/") for marker in GENERATED_PATH_MARKERS):
            return True
        header = "\n".join(snippet.splitlines()[:3]).lower()
        return any(marker in header for marker in GENERATED_HEADER_MARKERS)

    def _looks_like_helper(self, *, name: str | None, snippet: str) -> bool:
        """Return whether the node looks like a wrapper or helper."""

        normalized_name = (name or "").lower()
        normalized_snippet = snippet.lower()
        return any(hint in normalized_name or hint in normalized_snippet for hint in HELPER_HINTS)

    def _read_context_snippet(self, node: CodeContextNode) -> str:
        """Read snippet text for a context node when possible."""

        if self.snippet_reader is None:
            return node.name or ""
        return self.snippet_reader(node.file_path, node.line_start, node.line_end)

    def _read_node_snippet(self, node: Node) -> str:
        """Read snippet text for a graph node when possible."""

        if self.snippet_reader is None:
            return self._node_name(node) or ""
        file_path = self._node_file_path(node)
        if file_path is None:
            return self._node_name(node) or ""
        return self.snippet_reader(
            file_path, self._node_line_start(node), self._node_line_end(node)
        )

    @staticmethod
    def _enclosing_rank(node_kind: str | None, line_start: int, line_end: int) -> tuple[int, int]:
        """Return the enclosing node preference tuple."""

        span = line_end - line_start
        return (int(node_kind in FULL_CONTEXT_NODE_KINDS), span)

    @staticmethod
    def _paths_match(node_file: Path, target_file: Path) -> bool:
        """Return whether two paths are equal by exact or suffix-aware matching."""

        if node_file == target_file:
            return True
        node_parts = NodeRelevanceRankingService._path_parts(node_file)
        target_parts = NodeRelevanceRankingService._path_parts(target_file)
        if node_parts == target_parts:
            return True
        if len(node_parts) >= len(target_parts):
            return tuple(node_parts[-len(target_parts) :]) == target_parts
        return tuple(target_parts[-len(node_parts) :]) == node_parts

    @staticmethod
    def _path_parts(path: Path) -> tuple[str, ...]:
        """Normalize a path into comparable parts."""

        return tuple(part for part in path.as_posix().split("/") if part and part != ".")

    @staticmethod
    def _node_kind(node: Node) -> str | None:
        """Return the rankable node kind string."""

        return node.__class__.__name__

    @staticmethod
    def _node_name(node: Node) -> str | None:
        """Return the node name when available."""

        return getattr(node, "name", None)

    @staticmethod
    def _node_file_path(node: Node) -> Path | None:
        """Return the node file path when available."""

        file_path = getattr(node, "file_path", None)
        if file_path is None:
            return None
        return Path(file_path)

    @staticmethod
    def _node_line_start(node: Node) -> int | None:
        """Return the node line start when available."""

        return getattr(node, "line_start", None)

    @staticmethod
    def _node_line_end(node: Node) -> int | None:
        """Return the node line end when available."""

        return getattr(node, "line_end", None)

    @staticmethod
    def _update_graph_node_score(node: Node, *, new_score: float) -> Node:
        """Return a graph node copy with score applied when supported."""

        if isinstance(node, BaseCodeNode):
            return cast(Node, node.update_score(new_score))
        return node
