"""Map selection results back to a list of context nodes for rendering.

The output ordering is:
  1. Root-tagged selected candidates (first — preserves the "root pinned"
     invariant honored by every existing strategy).
  2. Non-root selected candidates, in selection order.
  3. Rejected candidates, in their original input order so the renderer's
     ``break``-on-overflow drops them deterministically.

Duplicates by ``CodeContextNode.identifier`` are collapsed: the first
appearance wins.
"""

from pydantic import BaseModel, ConfigDict

from models.base import NodeID
from models.context import CodeContextNode
from models.context_ranking import EvidenceRole, RankingCandidate


class NodeMapper(BaseModel):
    """Convert ``(selected, rejected)`` candidate lists into a ranked node list."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def map_to_nodes(
        self,
        selected: list[RankingCandidate],
        rejected: list[RankingCandidate],
    ) -> list[CodeContextNode]:
        """Return source nodes in the rendering-ready order described above."""

        roots = [c for c in selected if EvidenceRole.ROOT in c.roles]
        non_roots = [c for c in selected if EvidenceRole.ROOT not in c.roles]

        ordered: list[CodeContextNode] = []
        seen: set[NodeID] = set()
        for candidate in (*roots, *non_roots, *rejected):
            identifier = candidate.source_node.identifier
            if identifier in seen:
                continue
            seen.add(identifier)
            ordered.append(candidate.source_node)
        return ordered
