from collections.abc import Callable
from enum import StrEnum
from pathlib import Path

from models.context_ranking import BudgetedRankingConfig
from services.ranking.cpg_structural_ranking import CPGStructuralRankingStrategy
from services.ranking.evidence_ranking.strategy import (
    EvidenceAwareBudgetedNodeRankingStrategy,
)
from services.ranking.ranking import (
    ContextNodeRankingStrategy,
    DepthRepeatsContextNodeRankingStrategy,
    DummyNodeRankingStrategy,
    MultiplicativeBoostNodeRankingStrategy,
    NodeRelevanceRankingService,
    RandomNodeRankingStrategy,
)
from services.ranking.ranking_config import RankingCoefficients

RankingStrategyFactory = Callable[[Path], ContextNodeRankingStrategy]


class RankingStrategies(StrEnum):
    """Enum of available ranking strategies.
    Values are used in config and CLI, so they are fixed."""

    CURRENT = "current"
    DEPTH_REPEATS_CONTEXT = "depth_repeats_context"
    RANDOM_PICKING = "random_picking"
    MULTIPLICATIVE_BOOST = "multiplicative_boost"
    CPG_STRUCTURAL = "cpg_structural"
    EVIDENCE_BUDGETED = "evidence_budgeted"
    DUMMY = "dummy"


def _build_cpg_structural_ranking_strategy(
    repo_path: Path, cpg_structural_coefficients: Path | None = None
) -> ContextNodeRankingStrategy:
    if cpg_structural_coefficients is not None:
        coefficients = RankingCoefficients.from_yaml(cpg_structural_coefficients)
        return CPGStructuralRankingStrategy(
            project_root=repo_path,
            snippet_cache_max_entries=10000,
            coefficients=coefficients,
        )
    return CPGStructuralRankingStrategy(
        project_root=repo_path,
        snippet_cache_max_entries=10000,
    )


def _build_evidence_budgeted_strategy(
    repo_path: Path,
    token_budget: int,
    budgeted_ranking_config_path: Path | None = None,
) -> ContextNodeRankingStrategy:
    if budgeted_ranking_config_path is not None:
        config = BudgetedRankingConfig.from_yaml(budgeted_ranking_config_path)
    else:
        config = BudgetedRankingConfig()
    return EvidenceAwareBudgetedNodeRankingStrategy(
        project_root=repo_path,
        token_budget=token_budget,
        config=config,
    )


def _build_multiplicative_boost_ranking_strategy(
    repo_path: Path,
    multiplicative_boost_coefficients: Path | None = None,
) -> ContextNodeRankingStrategy:
    if multiplicative_boost_coefficients is not None:
        coefficients = RankingCoefficients.from_yaml(multiplicative_boost_coefficients)
        return MultiplicativeBoostNodeRankingStrategy(
            project_root=repo_path,
            snippet_cache_max_entries=10000,
            coefficients=coefficients,
        )
    return MultiplicativeBoostNodeRankingStrategy(
        project_root=repo_path,
        snippet_cache_max_entries=10000,
    )


def _build_depth_repeats_ranking_strategy(repo_path: Path) -> ContextNodeRankingStrategy:
    return DepthRepeatsContextNodeRankingStrategy(
        project_root=repo_path,
        snippet_cache_max_entries=10000,
    )


def build_strategy_factories(
    token_budget: int,
    seed: int | None = None,
    cpg_structural_coefficients: Path | None = None,
    budgeted_ranking_config_path: Path | None = None,
    multiplicative_boost_coefficients: Path | None = None,
) -> dict[str, RankingStrategyFactory]:
    return {
        RankingStrategies.CURRENT: lambda repo_path: NodeRelevanceRankingService(
            project_root=repo_path,
            snippet_cache_max_entries=10000,
        ),
        RankingStrategies.DEPTH_REPEATS_CONTEXT: _build_depth_repeats_ranking_strategy,
        RankingStrategies.RANDOM_PICKING: lambda repo_path: RandomNodeRankingStrategy(
            project_root=repo_path,
            snippet_cache_max_entries=10000,
            random_seed=seed,
        ),
        RankingStrategies.MULTIPLICATIVE_BOOST: (
            lambda repo_path: _build_multiplicative_boost_ranking_strategy(
                repo_path, multiplicative_boost_coefficients
            )
        ),
        RankingStrategies.CPG_STRUCTURAL: lambda repo_path: _build_cpg_structural_ranking_strategy(
            repo_path, cpg_structural_coefficients
        ),
        RankingStrategies.EVIDENCE_BUDGETED: lambda repo_path: _build_evidence_budgeted_strategy(
            repo_path, token_budget, budgeted_ranking_config_path
        ),
        RankingStrategies.DUMMY: lambda _repo_path: DummyNodeRankingStrategy(),
    }
