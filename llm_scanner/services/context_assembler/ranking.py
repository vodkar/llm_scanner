from __future__ import annotations

import math
import random
from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, PrivateAttr

from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.context import CodeContextNode
from models.edges.analysis import StaticAnalysisReports
from models.nodes import Node
from models.nodes.base import BaseCodeNode
from models.nodes.finding import BanditFindingNode, DlintFindingNode, FindingNode
from services.context_assembler.snippet_reader import SnippetReaderService

FINDING_EVIDENCE_WEIGHT: Final[float] = 0.20
SECURITY_PATH_WEIGHT: Final[float] = 0.15
TAINT_WEIGHT: Final[float] = 0.25
CONTEXT_WEIGHT: Final[float] = 0.35
FINDING_PROXIMITY_WEIGHT: Final[float] = 0.05

CONTEXT_DEPTH_WEIGHT: Final[float] = 0.45
CONTEXT_STRUCTURE_WEIGHT: Final[float] = 0.25
CONTEXT_FILE_PRIOR_WEIGHT: Final[float] = 0.30

SECURITY_BOOST_WEIGHT: Final[float] = 1.00

HOP_DECAY_BY_DEPTH: Final[dict[int, float]] = {
    0: 1.00,
    1: 0.85,
    2: 0.70,
    3: 0.55,
    4: 0.45,
}
HOP_DECAY_DEFAULT: Final[float] = 0.35
SEVERITY_SCORES: Final[dict[IssueSeverity, float]] = {
    IssueSeverity.LOW: 0.33,
    IssueSeverity.MEDIUM: 0.66,
    IssueSeverity.HIGH: 1.00,
}
CONFIDENCE_BY_SEVERITY: Final[dict[IssueSeverity, float]] = {
    IssueSeverity.LOW: 0.30,
    IssueSeverity.MEDIUM: 0.60,
    IssueSeverity.HIGH: 0.90,
}
DLINT_SEVERITY_BY_ISSUE_RANGE: Final[list[tuple[range, IssueSeverity]]] = [
    (range(100, 106), IssueSeverity.HIGH),
    (range(106, 111), IssueSeverity.MEDIUM),
    (range(111, 131), IssueSeverity.MEDIUM),
    (range(131, 138), IssueSeverity.LOW),
]
HIGH_RISK_CWES: Final[frozenset[int]] = frozenset(
    {
        22,
        77,
        78,
        79,
        89,
        94,
        95,
        98,
        113,
        185,
        200,
        209,
        215,
        259,
        327,
        338,
        502,
        611,
        703,
        918,
    }
)
RENDER_KIND_SCORES: Final[dict[str, float]] = {
    "FunctionNode": 1.00,
    "ClassNode": 0.80,
    "CodeBlockNode": 0.70,
    "VariableNode": 0.40,
}
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
TEST_FILE_PREFIXES: Final[tuple[str, ...]] = ("test_",)
TEST_FILE_SUFFIXES: Final[tuple[str, ...]] = ("_test.py",)
TEST_FILENAMES: Final[frozenset[str]] = frozenset({"conftest.py"})
TEST_PATH_MARKERS: Final[frozenset[str]] = frozenset({"tests", "__tests__"})


# Experiment results (2026-04-18, Claude model):
#   depth_repeats  0.650  <- best
#   mult_boost     0.610
#   dummy          0.530
#   current        0.510
#   random_pick    0.480
#
# Tuning applied (2026-04-18):
#   current:    raised security-tier sort threshold 0.0→0.5 (suppress single-keyword noise)
#               increased repeat_bonus weight 0.70→0.85 in _context_structure_score
#               SECURITY_PATH_WEIGHT 0.30→0.20, CONTEXT_WEIGHT 0.45→0.55
#   mult_boost: SECURITY_BOOST_WEIGHT 1.50→1.00 (reduce score clamping at the top)
#               added -repeats to sort key as tiebreaker after score+depth
#
# Run 2 results (2026-04-19, after Phase 0 coefficient tuning):
#   current        0.670  <- new best
#   depth_repeats  0.650
#   mult_boost     0.610
#   dummy          0.530
#   random_pick    0.480
#
# Phase 1 tuning (2026-04-19) — after current hit 0.670:
#   NEW signals:
#     - finding-proximity: severity-weighted graph distance; weight 0.05
#     - test/fixture downweight in _context_file_prior_score; penalty 0.15
#     - snippet-length penalty in _context_structure_score; 15% of structure
#   Weight rebalance on `current`:
#     FINDING_EVIDENCE_WEIGHT  0.25 → 0.15   (noisy; offload to proximity)
#     SECURITY_PATH_WEIGHT     0.20 → 0.15   (keyword heuristic noisy)
#     TAINT_WEIGHT             0.20 → 0.30   (strongest single signal)
#     CONTEXT_WEIGHT           0.35 → 0.35   (unchanged)
#     FINDING_PROXIMITY_WEIGHT   —  → 0.05   (new; severity-weighted reachability)
#   `mult_boost`, `depth_repeats`, `dummy`, `random_pick` untouched this phase.
#
# Run 3 results (2026-04-20, after Phase 1):
#   depth_repeats  0.598  (regressed -0.052 from Phase 0 — never touched!)
#   current        0.570  (regressed -0.100)
#   mult_boost     0.541  (regressed -0.069)
#
# Phase 1.5 correction (2026-04-20) — after Run 3 regressed all shared-helper strategies:
#   - Restored Phase 0's 0.85 repeat-bonus in _context_structure_score
#     (length_bonus was inadvertently stealing mass from repeats; removed pending
#     isolation as a standalone signal).
#   - Anchor-file exception on test-file penalty in _context_file_prior_score
#     (CleanVul puts target functions in test-named files; they were being demoted).
#   - Narrowed TEST_PATH_MARKERS to {"tests", "__tests__"} (dropped "test", "fixtures").
#   - Walked `current` weights halfway back:
#     FINDING_EVIDENCE_WEIGHT  0.15 → 0.20   (direct findings still the most reliable)
#     TAINT_WEIGHT             0.30 → 0.25   (taint may be sparse on this dataset)
#   - Replaced mult_boost linear form with tanh saturation so extreme security
#     signal no longer clamps away ordering.


class ContextNodeRankingStrategy(ABC):
    """Rank context nodes into a ready-to-render order."""

    @abstractmethod
    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Return context nodes in ready-to-use ranked order.

        Args:
            nodes: Retrieved context nodes.

        Returns:
            Ranked nodes ready for rendering.
        """


class NodeRelevanceRankingService(BaseModel, ContextNodeRankingStrategy):
    """Calculate security, context, and final ranking scores for one context."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path
    snippet_cache_max_entries: int = 10000

    _snippet_reader: SnippetReaderService = PrivateAttr()

    def model_post_init(self, __context: object) -> None:
        """Initialize the snippet reader owned by the ranking service."""

        del __context
        self._snippet_reader = SnippetReaderService(
            project_root=self.project_root,
            cache_max_entries=self.snippet_cache_max_entries,
        )

    def calculate_security_score(
        self,
        nodes: list[Node],
        finding_nodes: list[FindingNode],
        finding_edges: list[StaticAnalysisReports],
    ) -> list[Node]:
        """Calculate finding-derived security scores for nodes in one context."""

        if not nodes:
            return []

        findings_by_identifier = {str(finding.identifier): finding for finding in finding_nodes}
        direct_findings_by_node_id: dict[str, list[FindingNode]] = defaultdict(list)
        for edge in finding_edges:
            finding = findings_by_identifier.get(edge.src)
            if finding is None:
                continue
            direct_findings_by_node_id[str(edge.dst)].append(finding)

        scored_nodes: list[Node] = []
        for node in nodes:
            direct_findings = direct_findings_by_node_id.get(
                str(node.identifier),
                [],
            )
            finding_evidence_score = self._finding_evidence_score(direct_findings)
            security_path_score = self._security_path_score(
                snippet=self._read_context_snippet(node),
                direct_findings=direct_findings,
            )
            scored_nodes.append(
                node.update_scores(
                    finding_evidence_score=finding_evidence_score,
                    security_path_score=security_path_score,
                )
            )

        return scored_nodes

    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Return nodes ordered by the current root-first and final-score strategy.

        Args:
            nodes: Retrieved context nodes.

        Returns:
            Ranked nodes ready for rendering.
        """

        ranked_nodes = self.calculate_final_score(self.rank_context_nodes(nodes))
        return sorted(
            ranked_nodes,
            key=lambda item: (
                item.depth != 0,
                not (item.finding_evidence_score + item.security_path_score > 0.5),
                -item.score,
                item.depth,
                str(item.file_path),
                item.line_start,
            ),
        )

    def rank_context_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Calculate context-only scores for a single already-retrieved context.
        Returns only UNIQUE context nodes with repeats value updated"""

        if not nodes:
            return []

        aggregated_nodes = self._aggregate_context_nodes(nodes)
        anchor_files = self._anchor_files(aggregated_nodes)
        max_repeats = max((node.repeats for node in aggregated_nodes), default=0)
        scored_nodes: list[CodeContextNode] = []
        for node in aggregated_nodes:
            scored_nodes.append(
                node.model_copy(
                    update={
                        "context_score": self._context_score(
                            node=node,
                            anchor_files=anchor_files,
                            snippet=self._read_context_snippet(node),
                            max_repeats=max_repeats,
                        )
                    }
                )
            )

        return scored_nodes

    def _aggregate_context_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Merge repeated context nodes while preserving shallowest depth."""

        aggregated_by_id: dict[NodeID, CodeContextNode] = {}
        ordered_node_ids: list[NodeID] = []

        for node in nodes:
            existing_node = aggregated_by_id.get(node.identifier)
            if existing_node is None:
                aggregated_by_id[node.identifier] = node.model_copy()
                ordered_node_ids.append(node.identifier)
                continue

            existing_node.repeats += node.repeats + 1
            existing_node.depth = min(existing_node.depth, node.depth)

        return [aggregated_by_id[node_id] for node_id in ordered_node_ids]

    def calculate_final_score(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Compose final scores from previously computed score components."""

        final_nodes: list[CodeContextNode] = []
        for node in nodes:
            score = self._final_score(
                finding_evidence_score=node.finding_evidence_score,
                security_path_score=node.security_path_score,
                context_score=node.context_score,
                taint_score=node.taint_score,
                finding_proximity_score=node.finding_proximity_score,
            )
            final_nodes.append(node.model_copy(update={"score": score}))

        return final_nodes

    def _context_score(
        self,
        *,
        node: CodeContextNode,
        anchor_files: set[Path],
        snippet: str,
        max_repeats: int,
    ) -> float:
        """Calculate context-only relevance from a single context neighborhood."""

        depth_score = self._hop_decay(node.depth)
        structure_score = self._context_structure_score(
            node_kind=node.node_kind,
            repeats=node.repeats,
            max_repeats=max_repeats,
        )
        file_prior_score = self._context_file_prior_score(
            file_path=node.file_path,
            anchor_files=anchor_files,
            snippet=snippet,
        )
        return self._clamp_score(
            CONTEXT_DEPTH_WEIGHT * depth_score
            + CONTEXT_STRUCTURE_WEIGHT * structure_score
            + CONTEXT_FILE_PRIOR_WEIGHT * file_prior_score
        )

    def _final_score(
        self,
        *,
        finding_evidence_score: float,
        security_path_score: float,
        context_score: float,
        taint_score: float,
        finding_proximity_score: float,
    ) -> float:
        """Combine component scores into the final ranking score."""

        return self._clamp_score(
            FINDING_EVIDENCE_WEIGHT * finding_evidence_score
            + SECURITY_PATH_WEIGHT * security_path_score
            + TAINT_WEIGHT * taint_score
            + FINDING_PROXIMITY_WEIGHT * finding_proximity_score
            + CONTEXT_WEIGHT * context_score
        )

    def _finding_evidence_score(self, direct_findings: list[FindingNode]) -> float:
        """Score direct analyzer evidence attached to a node."""

        if not direct_findings:
            return 0.0

        severity_score = max(self._finding_severity(finding) for finding in direct_findings)
        confidence_score = max(self._finding_confidence(finding) for finding in direct_findings)
        has_bandit = any(isinstance(finding, BanditFindingNode) for finding in direct_findings)
        has_dlint = any(isinstance(finding, DlintFindingNode) for finding in direct_findings)
        if has_bandit and has_dlint:
            agreement_score = 1.00
        elif len(direct_findings) > 1:
            agreement_score = 0.30
        else:
            agreement_score = 0.00
        return self._clamp_score(
            0.50 * severity_score + 0.30 * confidence_score + 0.20 * agreement_score
        )

    def _security_path_score(self, *, snippet: str, direct_findings: list[FindingNode]) -> float:
        """Score sink, source, guard, and explicit path evidence heuristics."""

        normalized_text = snippet.lower()
        sink_indicator = 1.0 if any(hint in normalized_text for hint in SINK_HINTS) else 0.0
        source_indicator = 1.0 if any(hint in normalized_text for hint in SOURCE_HINTS) else 0.0
        guard_indicator = 1.0 if any(hint in normalized_text for hint in GUARD_HINTS) else 0.0
        security_path_evidence = 0.0
        if any(
            isinstance(finding, BanditFindingNode) and finding.cwe_id in HIGH_RISK_CWES
            for finding in direct_findings
        ):
            security_path_evidence = max(sink_indicator, 0.70)
        return self._clamp_score(
            0.35 * sink_indicator
            + 0.25 * source_indicator
            + 0.20 * guard_indicator
            + 0.20 * security_path_evidence
        )

    @staticmethod
    def _finding_severity(finding: FindingNode) -> float:
        """Return a normalized severity score for any finding type."""

        if isinstance(finding, BanditFindingNode):
            return SEVERITY_SCORES[finding.severity]
        if isinstance(finding, DlintFindingNode):
            severity = NodeRelevanceRankingService._dlint_severity(finding.issue_id)
            return SEVERITY_SCORES[severity]
        return 0.50

    @staticmethod
    def _finding_confidence(finding: FindingNode) -> float:
        """Return a confidence proxy derived from finding severity."""

        if isinstance(finding, BanditFindingNode):
            return CONFIDENCE_BY_SEVERITY[finding.severity]
        if isinstance(finding, DlintFindingNode):
            severity = NodeRelevanceRankingService._dlint_severity(finding.issue_id)
            return CONFIDENCE_BY_SEVERITY[severity]
        return 0.40

    @staticmethod
    def _dlint_severity(issue_id: int) -> IssueSeverity:
        """Map a Dlint issue ID to an approximate severity tier."""

        for id_range, severity in DLINT_SEVERITY_BY_ISSUE_RANGE:
            if issue_id in id_range:
                return severity
        return IssueSeverity.MEDIUM

    def _context_structure_score(
        self,
        *,
        node_kind: str | None,
        repeats: int,
        max_repeats: int,
    ) -> float:
        """Score node structure for final rendering usefulness."""

        repeat_bonus = min(1.0, repeats / max(max_repeats, 1))
        render_kind_bonus = RENDER_KIND_SCORES.get(node_kind or "", 0.20)
        return self._clamp_score(0.15 * render_kind_bonus + 0.85 * repeat_bonus)

    def _context_file_prior_score(
        self,
        *,
        file_path: Path,
        anchor_files: set[Path],
        snippet: str,
    ) -> float:
        """Score locality within the already-retrieved context."""

        same_file_bonus = (
            1.00 if any(self._paths_match(file_path, anchor) for anchor in anchor_files) else 0.00
        )
        same_module_bonus = max(
            (self._same_module_bonus(file_path, anchor) for anchor in anchor_files),
            default=0.00,
        )
        generated_penalty = (
            1.00 if self._is_generated_file(file_path=file_path, snippet=snippet) else 0.00
        )
        is_anchor = any(self._paths_match(file_path, anchor) for anchor in anchor_files)
        test_penalty = 0.00 if is_anchor else (1.00 if self._is_test_file(file_path) else 0.00)
        return self._clamp_score(
            max(
                0.0,
                0.70 * same_file_bonus
                + 0.20 * same_module_bonus
                - 0.10 * generated_penalty
                - 0.15 * test_penalty,
            )
        )

    def _anchor_files(self, nodes: list[CodeContextNode]) -> set[Path]:
        """Return the file set for the shallowest nodes in the context."""

        min_depth = min(node.depth for node in nodes)
        return {node.file_path for node in nodes if node.depth == min_depth}

    def _hop_decay(self, depth: int) -> float:
        """Return the configured hop decay for traversal depth."""

        return HOP_DECAY_BY_DEPTH.get(depth, HOP_DECAY_DEFAULT)

    def _same_module_bonus(self, file_path: Path, anchor_file: Path) -> float:
        """Approximate whether two files belong to the same module or package."""

        file_parts = self._path_parts(file_path)
        anchor_parts = self._path_parts(anchor_file)
        if not file_parts or not anchor_parts:
            return 0.0
        if file_parts[:-1] == anchor_parts[:-1]:
            return 1.0
        common_prefix = 0
        for file_part, anchor_part in zip(file_parts[:-1], anchor_parts[:-1], strict=False):
            if file_part != anchor_part:
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

    @staticmethod
    def _is_test_file(file_path: Path) -> bool:
        """Return whether the path looks like a test or fixture file (no I/O)."""

        filename = file_path.name
        if filename in TEST_FILENAMES:
            return True
        if any(filename.startswith(prefix) for prefix in TEST_FILE_PREFIXES):
            return True
        if any(filename.endswith(suffix) for suffix in TEST_FILE_SUFFIXES):
            return True
        parts = NodeRelevanceRankingService._path_parts(file_path)
        return any(part in TEST_PATH_MARKERS for part in parts)

    def _read_context_snippet(self, node: BaseCodeNode | CodeContextNode) -> str:
        """Read snippet text for a context node when possible."""

        return self._snippet_reader.read_snippet(node.file_path, node.line_start, node.line_end)

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
    def _clamp_score(score: float) -> float:
        """Clamp and round a score to the expected range."""

        return max(0.0, min(1.0, round(score, 6)))


class DepthRepeatsContextNodeRankingStrategy(NodeRelevanceRankingService):
    """Rank nodes by depth, repeats, and context score."""

    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Return nodes ordered by root priority, depth, repeats, and context score.

        Args:
            nodes: Retrieved context nodes.

        Returns:
            Ranked nodes ready for rendering.
        """

        ranked_nodes = self.rank_context_nodes(nodes)
        return sorted(
            ranked_nodes,
            key=lambda item: (
                item.depth != 0,
                item.depth,
                -item.repeats,
                -item.context_score,
            ),
        )


class RandomNodeRankingStrategy(NodeRelevanceRankingService):
    """Shuffle nodes while keeping root nodes ahead of non-root nodes."""

    random_seed: int | None = None

    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Return nodes shuffled within root and non-root groups.

        Args:
            nodes: Retrieved context nodes.

        Returns:
            Ranked nodes ready for rendering.
        """

        aggregated_nodes = self._aggregate_context_nodes(nodes)
        rng = random.Random(self.random_seed)
        root_nodes = [node for node in aggregated_nodes if node.depth == 0]
        other_nodes = [node for node in aggregated_nodes if node.depth != 0]
        rng.shuffle(root_nodes)
        rng.shuffle(other_nodes)
        return [*root_nodes, *other_nodes]


class MultiplicativeBoostNodeRankingStrategy(NodeRelevanceRankingService):
    """Rank nodes using context as base score with multiplicative security boost."""

    def calculate_final_score(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Compose final scores using tanh-saturating security boost over context base.

        Args:
            nodes: Nodes with context_score already calculated.

        Returns:
            Nodes with final score set via tanh-saturating formula.
        """

        final_nodes: list[CodeContextNode] = []
        for node in nodes:
            security_signal = node.finding_evidence_score + node.security_path_score
            saturated = math.tanh(SECURITY_BOOST_WEIGHT * security_signal)
            score = self._clamp_score(node.context_score * (1.0 + saturated))
            final_nodes.append(node.model_copy(update={"score": score}))
        return final_nodes

    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Return nodes ordered by root priority and multiplicative boost score.

        Args:
            nodes: Retrieved context nodes.

        Returns:
            Ranked nodes ready for rendering.
        """

        ranked_nodes = self.calculate_final_score(self.rank_context_nodes(nodes))
        return sorted(
            ranked_nodes,
            key=lambda item: (
                item.depth != 0,
                -item.score,
                item.depth,
                -item.repeats,
                str(item.file_path),
                item.line_start,
            ),
        )


class DummyNodeRankingStrategy(ContextNodeRankingStrategy):
    """Return nodes exactly as provided."""

    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Return the original list unchanged.

        Args:
            nodes: Retrieved context nodes.

        Returns:
            The same node list instance.
        """

        return nodes
