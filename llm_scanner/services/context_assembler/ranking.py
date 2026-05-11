import random
from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path
from typing import ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.context import CodeContextNode
from models.edges.analysis import StaticAnalysisReports
from models.nodes import Node
from models.nodes.base import BaseCodeNode
from models.nodes.finding import BanditFindingNode, DlintFindingNode, FindingNode
from services.context_assembler.ranking_config import (
    CombinerWeights,
    ContextBreakdown,
    EdgeDecayRates,
    EdgeTypeWeights,
    FilePriorBreakdown,
    FindingEvidenceBreakdown,
    RankingCoefficients,
    SecurityPathBreakdown,
    SeverityScoreMap,
    StructureBreakdown,
)
from services.context_assembler.snippet_reader import SnippetReaderService

FINDING_EVIDENCE_WEIGHT: Final[float] = 0.25
SECURITY_PATH_WEIGHT: Final[float] = 0.20
TAINT_WEIGHT: Final[float] = 0.20
CONTEXT_WEIGHT: Final[float] = 0.35

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
RENDER_KIND_DEFAULT_SCORE: Final[float] = 0.20
UNKNOWN_FINDING_SEVERITY_SCORE: Final[float] = 0.50
UNKNOWN_FINDING_CONFIDENCE_SCORE: Final[float] = 0.40
AGREEMENT_BOTH_ANALYZERS: Final[float] = 1.00
AGREEMENT_MULTIPLE_FINDINGS: Final[float] = 0.30
SECURITY_TIER_THRESHOLD: Final[float] = 0.5
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


def default_coefficients() -> RankingCoefficients:
    """Build a coefficients object that reproduces the hand-tuned Final constants.

    Returns:
        Coefficients whose numeric values match the module-level ``Final``
        constants exactly, so ``NodeRelevanceRankingService(coefficients=None)``
        stays byte-identical to the pre-refactor behavior.
    """

    return RankingCoefficients(
        combiner=CombinerWeights(
            finding_evidence=FINDING_EVIDENCE_WEIGHT,
            security_path=SECURITY_PATH_WEIGHT,
            taint=TAINT_WEIGHT,
            context=CONTEXT_WEIGHT,
        ),
        context_breakdown=ContextBreakdown(
            depth=CONTEXT_DEPTH_WEIGHT,
            structure=CONTEXT_STRUCTURE_WEIGHT,
            file_prior=CONTEXT_FILE_PRIOR_WEIGHT,
        ),
        finding_evidence_breakdown=FindingEvidenceBreakdown(
            severity=0.50,
            confidence=0.30,
            agreement=0.20,
        ),
        security_path_breakdown=SecurityPathBreakdown(
            sink=0.35,
            source=0.25,
            guard=0.20,
            path_evidence=0.20,
            high_risk_cwe_evidence_base=0.70,
        ),
        structure_breakdown=StructureBreakdown(
            render_kind=0.15,
            repeat_bonus=0.85,
        ),
        file_prior_breakdown=FilePriorBreakdown(
            same_file=0.70,
            same_module=0.20,
            generated_penalty=0.10,
        ),
        hop_decay_by_depth=dict(HOP_DECAY_BY_DEPTH),
        hop_decay_default=HOP_DECAY_DEFAULT,
        severity_scores=SeverityScoreMap(
            low=SEVERITY_SCORES[IssueSeverity.LOW],
            medium=SEVERITY_SCORES[IssueSeverity.MEDIUM],
            high=SEVERITY_SCORES[IssueSeverity.HIGH],
        ),
        confidence_by_severity=SeverityScoreMap(
            low=CONFIDENCE_BY_SEVERITY[IssueSeverity.LOW],
            medium=CONFIDENCE_BY_SEVERITY[IssueSeverity.MEDIUM],
            high=CONFIDENCE_BY_SEVERITY[IssueSeverity.HIGH],
        ),
        render_kind_scores=dict(RENDER_KIND_SCORES),
        security_boost_weight=SECURITY_BOOST_WEIGHT,
        security_tier_threshold=SECURITY_TIER_THRESHOLD,
        edge_type_weights=EdgeTypeWeights(
            flows_to=1.00,
            sanitized_by=0.85,
            calls=0.70,
            called_by=0.70,
            defined_by=0.60,
            used_by=0.55,
            contains=0.35,
        ),
        edge_decay_rates=EdgeDecayRates(
            flows_to=0.85,
            sanitized_by=0.80,
            calls=0.75,
            called_by=0.75,
            defined_by=0.70,
            used_by=0.70,
            contains=0.55,
        ),
        sanitizer_bypass_bonus=0.25,
        sanitizer_presence_damp=0.50,
        source_sink_path_max_depth=4,
    )


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


class ContextNodeRankingStrategy(ABC):
    """Rank context nodes into a ready-to-render order."""

    requires_edge_paths: ClassVar[bool] = False
    """When True, the assembler fetches per-edge-type depths for each node."""

    requires_taint_scores: ClassVar[bool] = False
    """When True, the assembler fetches backward-taint scores for each root."""

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

    requires_taint_scores: ClassVar[bool] = True

    project_root: Path
    snippet_cache_max_entries: int = 10000
    coefficients: RankingCoefficients = Field(default_factory=default_coefficients)

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
            key=lambda item: (item.depth != 0, -item.score, item.depth),
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
        context = self.coefficients.context_breakdown
        return self._clamp_score(
            context.depth * depth_score
            + context.structure * structure_score
            + context.file_prior * file_prior_score
        )

    def _final_score(
        self,
        *,
        finding_evidence_score: float,
        security_path_score: float,
        context_score: float,
        taint_score: float,
    ) -> float:
        """Combine component scores into the final ranking score."""

        combiner = self.coefficients.combiner
        return self._clamp_score(
            combiner.finding_evidence * finding_evidence_score
            + combiner.security_path * security_path_score
            + combiner.taint * taint_score
            + combiner.context * context_score
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
            agreement_score = AGREEMENT_BOTH_ANALYZERS
        elif len(direct_findings) > 1:
            agreement_score = AGREEMENT_MULTIPLE_FINDINGS
        else:
            agreement_score = 0.00
        evidence = self.coefficients.finding_evidence_breakdown
        return self._clamp_score(
            evidence.severity * severity_score
            + evidence.confidence * confidence_score
            + evidence.agreement * agreement_score
        )

    def _security_path_score(self, *, snippet: str, direct_findings: list[FindingNode]) -> float:
        """Score sink, source, guard, and explicit path evidence heuristics."""

        normalized_text = snippet.lower()
        sink_indicator = 1.0 if any(hint in normalized_text for hint in SINK_HINTS) else 0.0
        source_indicator = 1.0 if any(hint in normalized_text for hint in SOURCE_HINTS) else 0.0
        guard_indicator = 1.0 if any(hint in normalized_text for hint in GUARD_HINTS) else 0.0
        path = self.coefficients.security_path_breakdown
        security_path_evidence = 0.0
        if any(
            isinstance(finding, BanditFindingNode) and finding.cwe_id in HIGH_RISK_CWES
            for finding in direct_findings
        ):
            security_path_evidence = max(sink_indicator, path.high_risk_cwe_evidence_base)
        return self._clamp_score(
            path.sink * sink_indicator
            + path.source * source_indicator
            + path.guard * guard_indicator
            + path.path_evidence * security_path_evidence
        )

    def _finding_severity(self, finding: FindingNode) -> float:
        """Return a normalized severity score for any finding type."""

        if isinstance(finding, BanditFindingNode):
            return self._severity_score(finding.severity)
        if isinstance(finding, DlintFindingNode):
            severity = NodeRelevanceRankingService._dlint_severity(finding.issue_id)
            return self._severity_score(severity)
        return UNKNOWN_FINDING_SEVERITY_SCORE

    def _finding_confidence(self, finding: FindingNode) -> float:
        """Return a confidence proxy derived from finding severity."""

        if isinstance(finding, BanditFindingNode):
            return self._severity_confidence(finding.severity)
        if isinstance(finding, DlintFindingNode):
            severity = NodeRelevanceRankingService._dlint_severity(finding.issue_id)
            return self._severity_confidence(severity)
        return UNKNOWN_FINDING_CONFIDENCE_SCORE

    def _severity_score(self, severity: IssueSeverity) -> float:
        """Return the tunable severity score for a severity tier."""

        scores = self.coefficients.severity_scores
        if severity == IssueSeverity.LOW:
            return scores.low
        if severity == IssueSeverity.MEDIUM:
            return scores.medium
        return scores.high

    def _severity_confidence(self, severity: IssueSeverity) -> float:
        """Return the tunable confidence score for a severity tier."""

        scores = self.coefficients.confidence_by_severity
        if severity == IssueSeverity.LOW:
            return scores.low
        if severity == IssueSeverity.MEDIUM:
            return scores.medium
        return scores.high

    @staticmethod
    def _dlint_severity(issue_id: int) -> IssueSeverity:
        """Map a Dlint issue ID to an approximate severity tier."""

        for id_range, severity in DLINT_SEVERITY_BY_ISSUE_RANGE:
            if issue_id in id_range:
                return severity
        return IssueSeverity.MEDIUM

    def _context_structure_score(
        self, *, node_kind: str | None, repeats: int, max_repeats: int
    ) -> float:
        """Score node structure for final rendering usefulness."""

        repeat_bonus = min(1.0, repeats / max(max_repeats, 1))

        render_kind_bonus = self.coefficients.render_kind_scores.get(
            node_kind or "", RENDER_KIND_DEFAULT_SCORE
        )
        structure = self.coefficients.structure_breakdown
        return self._clamp_score(
            structure.render_kind * render_kind_bonus + structure.repeat_bonus * repeat_bonus
        )

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
        prior = self.coefficients.file_prior_breakdown
        return self._clamp_score(
            max(
                0.0,
                prior.same_file * same_file_bonus
                + prior.same_module * same_module_bonus
                - prior.generated_penalty * generated_penalty,
            )
        )

    def _anchor_files(self, nodes: list[CodeContextNode]) -> set[Path]:
        """Return the file set for the shallowest nodes in the context."""

        min_depth = min(node.depth for node in nodes)
        return {node.file_path for node in nodes if node.depth == min_depth}

    def _hop_decay(self, depth: int) -> float:
        """Return the configured hop decay for traversal depth."""

        return self.coefficients.hop_decay_by_depth.get(depth, self.coefficients.hop_decay_default)

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
        """Compose final scores using multiplicative security boost over context base.

        Args:
            nodes: Nodes with context_score already calculated.

        Returns:
            Nodes with final score set via multiplicative formula.
        """

        final_nodes: list[CodeContextNode] = []
        security_boost = self.coefficients.security_boost_weight
        for node in nodes:
            security_signal = node.finding_evidence_score + node.security_path_score
            score = self._clamp_score(node.context_score * (1.0 + security_boost * security_signal))
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
            key=lambda item: (item.depth != 0, -item.score, item.depth),
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
