"""Evidence-aware budgeted ranking strategy — orchestrates the new pipeline.

Wires the candidate builder, semantic annotator, scorers, budgeted selector,
and node mapper into a single ``rank_nodes`` call. Lives in its own package so
no scoring helper is shared with existing strategies (``NodeRelevanceRankingService``,
``CPGStructuralRankingStrategy``, …) — that isolation guards against the
shared-helper regression that hit Phase 1.
"""

from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from models.context import CodeContextNode
from models.context_ranking import BudgetedRankingConfig
from services.context_assembler.evidence_ranking import budgeted_selector as bs
from services.context_assembler.evidence_ranking import candidate_builder as cb
from services.context_assembler.evidence_ranking import context_scorer as cs
from services.context_assembler.evidence_ranking import evidence_scorer as es
from services.context_assembler.evidence_ranking import graph_distance_scorer as gd
from services.context_assembler.evidence_ranking import node_mapper as nm
from services.context_assembler.evidence_ranking import semantic_annotator as sa
from services.context_assembler.ranking import ContextNodeRankingStrategy
from services.context_assembler.snippet_reader import SnippetReaderService


class EvidenceAwareBudgetedNodeRankingStrategy(BaseModel, ContextNodeRankingStrategy):
    """Rank context nodes via evidence-aware noisy-OR scoring + greedy budgeted selection."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    requires_edge_paths: ClassVar[bool] = True

    project_root: Path
    token_budget: int = Field(..., gt=0)
    config: BudgetedRankingConfig = Field(default_factory=BudgetedRankingConfig)
    snippet_cache_max_entries: int = 10_000

    _snippet_reader: SnippetReaderService = PrivateAttr()
    _builder: cb.CandidateBuilder = PrivateAttr()
    _annotator: sa.SemanticAnnotator = PrivateAttr()
    _context_scorer: cs.ContextScorer = PrivateAttr()
    _selector: bs.BudgetedSelector = PrivateAttr()
    _mapper: nm.NodeMapper = PrivateAttr()

    def model_post_init(self, _context: object) -> None:
        """Construct the per-strategy pipeline components."""

        self._snippet_reader = SnippetReaderService(
            project_root=self.project_root,
            cache_max_entries=self.snippet_cache_max_entries,
        )
        self._builder = cb.CandidateBuilder(
            project_root=self.project_root,
            config=self.config,
            snippet_reader=self._snippet_reader,
        )
        self._annotator = sa.SemanticAnnotator(
            project_root=self.project_root,
            snippet_reader=self._snippet_reader,
        )
        self._context_scorer = cs.ContextScorer(
            project_root=self.project_root,
            snippet_reader=self._snippet_reader,
        )
        self._selector = bs.BudgetedSelector(config=self.config)
        self._mapper = nm.NodeMapper()

    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        """Rank candidates and return them in render order."""

        if not nodes:
            return []

        candidates = self._builder.build(nodes)
        candidates = self._annotator.annotate(candidates)

        context_scores = self._context_scorer.score_all(candidates)
        scored: list = []
        for candidate, ctx_score in zip(candidates, context_scores, strict=True):
            distance_score = gd.score(candidate, self.config)
            updated = candidate.model_copy(
                update={"distance_score": distance_score, "context_score": ctx_score}
            )
            relevance = es.score(updated, self.config)
            scored.append(updated.model_copy(update={"relevance": relevance}))

        selected, rejected = self._selector.select(scored, self.token_budget)
        return self._mapper.map_to_nodes(selected, rejected)
