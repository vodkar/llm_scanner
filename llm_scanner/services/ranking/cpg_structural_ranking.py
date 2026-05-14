"""Edge-type-aware ranking strategy for CPG context nodes."""

from pathlib import Path
from typing import ClassVar, Final

from models.context import CodeContextNode
from services.ranking.ranking import (
    SINK_HINTS,
    SOURCE_HINTS,
    NodeRelevanceRankingService,
)

FLOWS_TO_EDGE: Final[str] = "FLOWS_TO"
SANITIZED_BY_EDGE: Final[str] = "SANITIZED_BY"


class CPGStructuralRankingStrategy(NodeRelevanceRankingService):
    """Rank context nodes using per-edge-type decayed contributions.

    Unlike :class:`NodeRelevanceRankingService`, which scores depth as an
    edge-blind hop decay, this strategy consumes the ``edge_depths`` populated
    by :py:meth:`ContextRepository.fetch_code_neighborhood_with_edge_paths` and
    scores the depth component as the strongest edge-specific signal
    (``max`` over ``edge_type_weight[et] * edge_decay_rate[et] ** depth_via_et``).
    A source-sink path detected via ``FLOWS_TO`` edges yields an additional
    bonus on the security-path score, dampened when a ``SANITIZED_BY`` edge is
    also present on the path.
    """

    requires_edge_paths: ClassVar[bool] = True

    def _context_score(
        self,
        *,
        node: CodeContextNode,
        anchor_files: set[Path],
        snippet: str,
        max_repeats: int,
    ) -> float:
        """Calculate edge-aware context relevance for a single neighborhood."""

        depth_score = self._edge_aware_depth_score(node)
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

    def _edge_aware_depth_score(self, node: CodeContextNode) -> float:
        """Return the max per-edge-type weighted + decayed contribution."""

        if node.depth == 0:
            return 1.0

        edge_depths = node.edge_depths
        if not edge_depths:
            return self._hop_decay(node.depth)

        weights = self.coefficients.edge_type_weights.model_dump()
        decay_rates = self.coefficients.edge_decay_rates.model_dump()

        best_score = 0.0
        for edge_type, edge_depth in edge_depths.items():
            lower_key = edge_type.lower()
            weight = weights.get(lower_key)
            decay = decay_rates.get(lower_key)
            if weight is None or decay is None:
                continue
            contribution = weight * (decay ** max(0, edge_depth))
            if contribution > best_score:
                best_score = contribution
        return self._clamp_score(best_score)

    def rank_context_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Score context-only relevance and add source-sink path bonuses."""

        scored = super().rank_context_nodes(nodes)
        if not scored:
            return scored

        sink_ids, source_ids = self._classify_sink_source_nodes(scored)
        if not sink_ids or not source_ids:
            return scored

        max_depth = self.coefficients.source_sink_path_max_depth
        enhanced: list[CodeContextNode] = []
        for node in scored:
            bonus = self._source_sink_flow_bonus(
                node=node, sink_ids=sink_ids, source_ids=source_ids, max_depth=max_depth
            )
            if bonus <= 0.0:
                enhanced.append(node)
                continue
            updated_security = self._clamp_score(node.security_path_score + bonus)
            enhanced.append(node.model_copy(update={"security_path_score": updated_security}))
        return enhanced

    def _classify_sink_source_nodes(
        self, nodes: list[CodeContextNode]
    ) -> tuple[set[str], set[str]]:
        """Partition node identifiers into sink-like and source-like roles."""

        sink_ids: set[str] = set()
        source_ids: set[str] = set()
        for node in nodes:
            snippet = self._read_context_snippet(node).lower()
            if any(hint in snippet for hint in SINK_HINTS):
                sink_ids.add(str(node.identifier))
            if any(hint in snippet for hint in SOURCE_HINTS):
                source_ids.add(str(node.identifier))
        return sink_ids, source_ids

    def _source_sink_flow_bonus(
        self,
        *,
        node: CodeContextNode,
        sink_ids: set[str],
        source_ids: set[str],
        max_depth: int,
    ) -> float:
        """Return a positive bonus when ``node`` sits on a FLOWS_TO source-sink path.

        Approximation: the node must be reachable via ``FLOWS_TO`` within
        ``max_depth``. When a ``SANITIZED_BY`` edge is also present within the
        same depth budget, the bonus is damped by
        ``sanitizer_presence_damp``.
        """

        edge_depths = node.edge_depths or {}
        flows_depth = edge_depths.get(FLOWS_TO_EDGE)
        if flows_depth is None or flows_depth > max_depth:
            return 0.0
        if not sink_ids or not source_ids:
            return 0.0

        bonus = self.coefficients.sanitizer_bypass_bonus
        sanitized_depth = edge_depths.get(SANITIZED_BY_EDGE)
        if sanitized_depth is not None and sanitized_depth <= max_depth:
            bonus *= self.coefficients.sanitizer_presence_damp
        return bonus

    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Return nodes ordered by the edge-aware composite score."""

        ranked_nodes = self.calculate_final_score(self.rank_context_nodes(nodes))
        security_threshold = self.coefficients.security_tier_threshold
        return sorted(
            ranked_nodes,
            key=lambda item: (
                item.depth != 0,
                not (item.finding_evidence_score + item.security_path_score > security_threshold),
                -item.score,
                item.depth,
                str(item.file_path),
                item.line_start,
            ),
        )
