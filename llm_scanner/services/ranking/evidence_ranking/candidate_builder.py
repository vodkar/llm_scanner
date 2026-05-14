"""Build :class:`RankingCandidate` instances from raw context nodes.

This module produces exactly **one** candidate per source ``CodeContextNode``.
Sub-candidate splitting (suggested by ``max_candidates_per_node`` in
``BudgetedRankingConfig``) is intentionally deferred to a later iteration —
the existing renderer stitches snippets by ``file_path`` and de-duplicates by
``identifier``, which is incompatible with multiple sub-candidates per node.

Token estimation here uses the same ``max(1, len(text) // 3)`` formula as the
context assembler's renderer (``context_assembler.py:170-183``) so the
budgeted selector's accounting matches what actually gets rendered.
"""

from collections import OrderedDict
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from models.base import NodeID
from models.context import CodeContextNode
from models.context_ranking import BudgetedRankingConfig, RankingCandidate
from services.snippet_reader import SnippetReaderService


def estimate_tokens(text: str) -> int:
    """Estimate token count using the same heuristic as the renderer.

    See ``ContextAssemblerService._estimate_tokens`` at
    ``context_assembler.py:170-183``.
    """

    return max(1, len(text) // 3) if text else 0


class CandidateBuilder(BaseModel):
    """Convert raw context nodes into one ``RankingCandidate`` apiece."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path
    config: BudgetedRankingConfig
    snippet_reader: SnippetReaderService

    def build(self, nodes: list[CodeContextNode]) -> list[RankingCandidate]:
        """Produce one candidate per unique node, preserving first-seen order."""

        if not nodes:
            return []

        unique_nodes = self._aggregate(nodes)
        return [self._make_candidate(node) for node in unique_nodes]

    def _aggregate(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Collapse duplicate identifiers, keeping shallowest depth and summed repeats.

        Mirrors the logic of ``NodeRelevanceRankingService._aggregate_context_nodes``
        at ``ranking.py:368-384`` so the new strategy sees the same de-duplication
        invariants as existing strategies.
        """

        aggregated: OrderedDict[NodeID, CodeContextNode] = OrderedDict()
        for node in nodes:
            existing = aggregated.get(node.identifier)
            if existing is None:
                aggregated[node.identifier] = node.model_copy()
                continue
            existing.repeats += node.repeats + 1
            existing.depth = min(existing.depth, node.depth)
        return list(aggregated.values())

    def _make_candidate(self, node: CodeContextNode) -> RankingCandidate:
        """Build a single candidate, clipping its line range when oversized."""

        snippet = self.snippet_reader.read_snippet(node.file_path, node.line_start, node.line_end)
        full_tokens = estimate_tokens(snippet)

        if full_tokens <= self.config.small_node_token_threshold:
            return RankingCandidate(
                source_node=node,
                roles=frozenset(),
                estimated_token_count=full_tokens,
                clipped_line_start=node.line_start,
                clipped_line_end=node.line_end,
            )

        radius = self.config.local_window_radius
        clipped_start = max(1, node.line_start - radius)
        clipped_end = max(clipped_start, node.line_start + radius)
        clipped_snippet = self.snippet_reader.read_snippet(
            node.file_path, clipped_start, clipped_end
        )

        return RankingCandidate(
            source_node=node,
            roles=frozenset(),
            estimated_token_count=estimate_tokens(clipped_snippet),
            clipped_line_start=clipped_start,
            clipped_line_end=clipped_end,
        )
