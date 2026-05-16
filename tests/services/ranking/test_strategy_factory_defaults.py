"""Tests for the ``_default`` ranking-strategy variants in ``build_strategy_factories``."""

from pathlib import Path

from services.ranking.ranking import (
    MultiplicativeBoostNodeRankingStrategy,
    NodeRelevanceRankingService,
)
from services.ranking.ranking_config import RankingCoefficients
from services.ranking.strategy_factory import RankingStrategies, build_strategy_factories

_BASE_COEFFICIENTS_PATH = (
    Path(__file__).resolve().parents[3] / "config" / "ranking_coefficients_cpg_structural.yaml"
)


def _tuned_yaml(tmp_path: Path) -> Path:
    """Write a base coefficients YAML with a recognizable security_boost_weight."""

    base = RankingCoefficients.from_yaml(_BASE_COEFFICIENTS_PATH)
    tuned = base.model_copy(update={"security_boost_weight": 2.75})
    out = tmp_path / "tuned.yaml"
    tuned.to_yaml(out)
    return out


def test_factory_exposes_both_current_and_current_default_keys() -> None:
    """Both keys must be present so they end up in separate dataset files."""

    factories = build_strategy_factories(token_budget=2048)

    assert RankingStrategies.CURRENT in factories
    assert RankingStrategies.CURRENT_DEFAULT in factories
    assert RankingStrategies.MULTIPLICATIVE_BOOST in factories
    assert RankingStrategies.MULTIPLICATIVE_BOOST_DEFAULT in factories


def test_default_variants_ignore_tuned_yaml(tmp_path: Path) -> None:
    """``*_default`` strategies must keep built-in coefficients even when a tuned YAML is set."""

    coeff_path = _tuned_yaml(tmp_path)
    factories = build_strategy_factories(
        token_budget=2048,
        current_coefficients=coeff_path,
        multiplicative_boost_coefficients=coeff_path,
    )

    current_tuned = factories[RankingStrategies.CURRENT](tmp_path)
    current_default = factories[RankingStrategies.CURRENT_DEFAULT](tmp_path)
    mboost_tuned = factories[RankingStrategies.MULTIPLICATIVE_BOOST](tmp_path)
    mboost_default = factories[RankingStrategies.MULTIPLICATIVE_BOOST_DEFAULT](tmp_path)

    assert isinstance(current_tuned, NodeRelevanceRankingService)
    assert isinstance(current_default, NodeRelevanceRankingService)
    assert isinstance(mboost_tuned, MultiplicativeBoostNodeRankingStrategy)
    assert isinstance(mboost_default, MultiplicativeBoostNodeRankingStrategy)

    # Tuned variants pick up the YAML value.
    assert current_tuned.coefficients.security_boost_weight == 2.75
    assert mboost_tuned.coefficients.security_boost_weight == 2.75

    # Default variants ignore the YAML and keep their built-in coefficients.
    builtin = NodeRelevanceRankingService(project_root=tmp_path).coefficients
    assert current_default.coefficients.security_boost_weight == builtin.security_boost_weight
    assert mboost_default.coefficients.security_boost_weight == builtin.security_boost_weight


def test_default_variants_use_builtin_when_no_yaml_supplied(tmp_path: Path) -> None:
    """Without any tuned YAML, default and tuned variants should agree."""

    factories = build_strategy_factories(token_budget=2048)

    current_tuned = factories[RankingStrategies.CURRENT](tmp_path)
    current_default = factories[RankingStrategies.CURRENT_DEFAULT](tmp_path)

    assert isinstance(current_tuned, NodeRelevanceRankingService)
    assert isinstance(current_default, NodeRelevanceRankingService)
    assert current_tuned.coefficients == current_default.coefficients
