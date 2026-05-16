from collections.abc import Callable
from enum import StrEnum
from functools import partial
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
    Values are used in config and CLI, so they are fixed.

    The ``_DEFAULT`` variants always use the built-in coefficients regardless
    of any tuned YAML supplied on the CLI, so a single ``compare-rankings``
    run can produce side-by-side datasets for the tuned and untuned variants.
    """

    CURRENT = "current"
    CURRENT_DEFAULT = "current_default"
    DEPTH_REPEATS_CONTEXT = "depth_repeats_context"
    RANDOM_PICKING = "random_picking"
    MULTIPLICATIVE_BOOST = "multiplicative_boost"
    MULTIPLICATIVE_BOOST_DEFAULT = "multiplicative_boost_default"
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


def _build_current_ranking_strategy(
    repo_path: Path,
    current_coefficients: Path | None = None,
) -> ContextNodeRankingStrategy:
    if current_coefficients is not None:
        coefficients = RankingCoefficients.from_yaml(current_coefficients)
        return NodeRelevanceRankingService(
            project_root=repo_path,
            snippet_cache_max_entries=10000,
            coefficients=coefficients,
        )
    return NodeRelevanceRankingService(
        project_root=repo_path,
        snippet_cache_max_entries=10000,
    )


def _build_depth_repeats_ranking_strategy(repo_path: Path) -> ContextNodeRankingStrategy:
    return DepthRepeatsContextNodeRankingStrategy(
        project_root=repo_path,
        snippet_cache_max_entries=10000,
    )


def _build_current_default_ranking_strategy(repo_path: Path) -> ContextNodeRankingStrategy:
    """Build the ``current`` strategy with its built-in default coefficients.

    This factory ignores any ``--current-coefficients`` YAML so that a single
    ``compare-rankings`` run produces a side-by-side default-vs-tuned dataset.
    """

    return NodeRelevanceRankingService(
        project_root=repo_path,
        snippet_cache_max_entries=10000,
    )


def _build_multiplicative_boost_default_ranking_strategy(
    repo_path: Path,
) -> ContextNodeRankingStrategy:
    """Build ``multiplicative_boost`` with its built-in default coefficients.

    Ignores any ``--multiplicative-boost-coefficients`` YAML so a single
    ``compare-rankings`` run produces a side-by-side default-vs-tuned dataset.
    """

    return MultiplicativeBoostNodeRankingStrategy(
        project_root=repo_path,
        snippet_cache_max_entries=10000,
    )


def _build_random_picking_ranking_strategy(
    repo_path: Path, seed: int | None = None
) -> ContextNodeRankingStrategy:
    return RandomNodeRankingStrategy(
        project_root=repo_path,
        snippet_cache_max_entries=10000,
        random_seed=seed,
    )


def _build_dummy_ranking_strategy(_repo_path: Path) -> ContextNodeRankingStrategy:
    return DummyNodeRankingStrategy()


def build_strategy_factories(
    token_budget: int,
    seed: int | None = None,
    cpg_structural_coefficients: Path | None = None,
    budgeted_ranking_config_path: Path | None = None,
    multiplicative_boost_coefficients: Path | None = None,
    current_coefficients: Path | None = None,
) -> dict[str, RankingStrategyFactory]:
    return {
        RankingStrategies.CURRENT: partial(
            _build_current_ranking_strategy,
            current_coefficients=current_coefficients,
        ),
        RankingStrategies.CURRENT_DEFAULT: _build_current_default_ranking_strategy,
        RankingStrategies.DEPTH_REPEATS_CONTEXT: _build_depth_repeats_ranking_strategy,
        RankingStrategies.RANDOM_PICKING: partial(
            _build_random_picking_ranking_strategy,
            seed=seed,
        ),
        RankingStrategies.MULTIPLICATIVE_BOOST: partial(
            _build_multiplicative_boost_ranking_strategy,
            multiplicative_boost_coefficients=multiplicative_boost_coefficients,
        ),
        RankingStrategies.MULTIPLICATIVE_BOOST_DEFAULT: (
            _build_multiplicative_boost_default_ranking_strategy
        ),
        RankingStrategies.CPG_STRUCTURAL: partial(
            _build_cpg_structural_ranking_strategy,
            cpg_structural_coefficients=cpg_structural_coefficients,
        ),
        RankingStrategies.EVIDENCE_BUDGETED: partial(
            _build_evidence_budgeted_strategy,
            token_budget=token_budget,
            budgeted_ranking_config_path=budgeted_ranking_config_path,
        ),
        RankingStrategies.DUMMY: _build_dummy_ranking_strategy,
    }
