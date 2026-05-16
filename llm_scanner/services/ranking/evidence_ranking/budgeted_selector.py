"""Greedy budgeted selector — picks candidates by gain, respects token budget.

The selector iterates: per round, compute each remaining candidate's
*gain* (relevance × role-coverage × redundancy-penalty / tokens^p), pick the
best, accumulate into the selected set, recompute role coverage and
redundancy. Stop when no remaining candidate fits the safety-budgeted
allowance.

Tie-breaking is deterministic on ``(-relevance, str(file_path), line_start)``
to keep selection reproducible across runs.
"""

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from models.context_ranking import (
    BudgetedRankingConfig,
    EvidenceRole,
    RankingCandidate,
)


class BudgetedSelector(BaseModel):
    """Greedy gain-based selector with role-coverage and redundancy shaping."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    config: BudgetedRankingConfig

    def select(
        self,
        candidates: list[RankingCandidate],
        token_budget: int,
    ) -> tuple[list[RankingCandidate], list[RankingCandidate]]:
        """Return ``(selected, rejected)`` for the given candidate list."""

        if not candidates:
            return [], []

        effective_budget = max(1, int(token_budget * self.config.budget_safety_ratio))

        selected: list[RankingCandidate] = []
        selected_roles: set[EvidenceRole] = set()
        line_index: dict[Path, set[int]] = {}
        used_tokens = 0
        remaining = list(candidates)

        while remaining:
            best_index = -1
            best_key: tuple[float, float, str, int] | None = None

            for index, candidate in enumerate(remaining):
                tokens = candidate.estimated_token_count
                if used_tokens + tokens > effective_budget:
                    continue

                gain = self._gain(candidate, selected_roles, line_index)
                key = (
                    -gain,
                    -candidate.relevance,
                    str(candidate.source_node.file_path),
                    candidate.source_node.line_start,
                )
                if best_key is None or key < best_key:
                    best_key = key
                    best_index = index

            if best_index < 0:
                break

            chosen = remaining.pop(best_index)
            selected.append(chosen)
            selected_roles |= chosen.roles
            used_tokens += chosen.estimated_token_count
            self._record_lines(chosen, line_index)

        return selected, remaining

    def _gain(
        self,
        candidate: RankingCandidate,
        selected_roles: set[EvidenceRole],
        line_index: dict[Path, set[int]],
    ) -> float:
        new_roles = candidate.roles - selected_roles
        coverage_mult = 1.0 + self.config.role_coverage_bonus * len(new_roles)

        redundancy = self._redundancy(candidate, line_index)
        redundancy_penalty = max(0.0, 1.0 - self.config.novelty_penalty * redundancy)

        denominator = max(1.0, candidate.estimated_token_count**self.config.token_cost_power)
        return candidate.relevance * coverage_mult * redundancy_penalty / denominator

    @staticmethod
    def _candidate_lines(candidate: RankingCandidate) -> set[int]:
        return set(range(candidate.clipped_line_start, candidate.clipped_line_end + 1))

    @classmethod
    def _redundancy(
        cls,
        candidate: RankingCandidate,
        line_index: dict[Path, set[int]],
    ) -> float:
        existing = line_index.get(candidate.source_node.file_path)
        if not existing:
            return 0.0
        candidate_lines = cls._candidate_lines(candidate)
        if not candidate_lines:
            return 0.0
        intersection = len(candidate_lines & existing)
        union = len(candidate_lines | existing)
        return intersection / union if union else 0.0

    @classmethod
    def _record_lines(
        cls,
        candidate: RankingCandidate,
        line_index: dict[Path, set[int]],
    ) -> None:
        existing = line_index.setdefault(candidate.source_node.file_path, set())
        existing.update(cls._candidate_lines(candidate))
