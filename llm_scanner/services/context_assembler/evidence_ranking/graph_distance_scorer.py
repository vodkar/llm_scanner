"""Graph-distance scoring for ranking candidates.

The score attenuates with distance from the root finding using
``config.depth_decay``. When per-edge-type depths are available
(``CodeContextNode.edge_depths``) the strongest edge wins — a node that's one
hop away on a high-signal edge (e.g. ``FLOWS_TO``) outranks one a single hop
away on a low-signal edge (e.g. ``CONTAINS``).
"""

from models.context_ranking import BudgetedRankingConfig, RankingCandidate


def score(candidate: RankingCandidate, config: BudgetedRankingConfig) -> float:
    """Return the graph-distance attenuation factor for this candidate."""

    edge_depths = candidate.source_node.edge_depths
    if edge_depths:
        return max(config.depth_decay**depth for depth in edge_depths.values())
    return config.depth_decay**candidate.source_node.depth
