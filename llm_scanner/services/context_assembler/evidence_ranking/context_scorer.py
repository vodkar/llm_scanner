"""Context-only scoring (file locality + structural prior).

The formula is *copied* from ``NodeRelevanceRankingService._context_score``
rather than imported, to honor the project rule that scoring helpers are not
shared across strategies (see ``docs/ranking_system.md`` and the Phase 1
regression note in memory).
"""

from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict

from models.context_ranking import EvidenceRole, RankingCandidate
from services.context_assembler.ranking import (
    RENDER_KIND_DEFAULT_SCORE,
    RENDER_KIND_SCORES,
)
from services.context_assembler.snippet_reader import SnippetReaderService

_SAME_FILE_BONUS: Final[float] = 0.70
_SAME_MODULE_FULL_BONUS: Final[float] = 0.20
_SAME_MODULE_PARTIAL_BONUS: Final[float] = 0.10
_RENDER_KIND_WEIGHT: Final[float] = 0.55
_REPEAT_BONUS_WEIGHT: Final[float] = 0.45


class ContextScorer(BaseModel):
    """Compute a per-candidate context-only relevance score in [0, 1]."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path
    snippet_reader: SnippetReaderService

    def score_all(self, candidates: list[RankingCandidate]) -> list[float]:
        """Score a batch in one pass so per-batch normalization can be applied."""

        if not candidates:
            return []

        max_repeats = max(c.source_node.repeats for c in candidates) or 1
        anchor_files = self._anchor_files(candidates)
        return [self._score_one(c, anchor_files, max_repeats) for c in candidates]

    def _score_one(
        self,
        candidate: RankingCandidate,
        anchor_files: set[Path],
        max_repeats: int,
    ) -> float:
        node = candidate.source_node
        kind_score = RENDER_KIND_SCORES.get(node.node_kind or "", RENDER_KIND_DEFAULT_SCORE)
        repeat_ratio = min(1.0, node.repeats / max_repeats) if max_repeats else 0.0
        structure = _RENDER_KIND_WEIGHT * kind_score + _REPEAT_BONUS_WEIGHT * repeat_ratio

        file_bonus = 0.0
        if any(self._paths_match(node.file_path, anchor) for anchor in anchor_files):
            file_bonus += _SAME_FILE_BONUS
        elif anchor_files:
            module_score = max(
                self._module_score(node.file_path, anchor) for anchor in anchor_files
            )
            file_bonus += module_score

        # Boilerplate gets penalized; everything else clamped at [0, 1].
        if EvidenceRole.BOILERPLATE in candidate.roles:
            return 0.0
        return min(1.0, max(0.0, 0.5 * structure + 0.5 * file_bonus))

    @staticmethod
    def _anchor_files(candidates: list[RankingCandidate]) -> set[Path]:
        """The files of root (depth=0) candidates; falls back to shallowest depth."""

        roots = [c.source_node for c in candidates if c.source_node.depth == 0]
        if roots:
            return {n.file_path for n in roots}
        if not candidates:
            return set()
        shallowest = min(c.source_node.depth for c in candidates)
        return {c.source_node.file_path for c in candidates if c.source_node.depth == shallowest}

    @staticmethod
    def _paths_match(node_file: Path, anchor: Path) -> bool:
        return node_file == anchor or node_file.as_posix().endswith(anchor.as_posix())

    @staticmethod
    def _module_score(node_file: Path, anchor: Path) -> float:
        node_parts = node_file.parts
        anchor_parts = anchor.parts
        if not node_parts or not anchor_parts:
            return 0.0
        if node_parts[:-1] == anchor_parts[:-1]:
            return _SAME_MODULE_FULL_BONUS
        common = 0
        for np, ap in zip(node_parts[:-1], anchor_parts[:-1], strict=False):
            if np != ap:
                break
            common += 1
        return _SAME_MODULE_PARTIAL_BONUS if common > 0 else 0.0
