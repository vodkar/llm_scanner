"""Unit tests for the Optuna best_params → coefficients YAML helpers."""

from pathlib import Path

import optuna

from models.context_ranking import BudgetedRankingConfig
from services.ranking.evidence_ranking.utils import (
    budgeted_config_from_best_params,
    coefficients_from_best_params,
    suggest_multiplicative_boost_coefficients,
)
from services.ranking.ranking_config import RankingCoefficients

_BASE_COEFFICIENTS_PATH = (
    Path(__file__).resolve().parents[4] / "config" / "ranking_coefficients_cpg_structural.yaml"
)


def test_coefficients_from_best_params_writes_dotted_keys_into_sections() -> None:
    """Dotted keys should land in the nested section; flat keys at the top."""

    base = RankingCoefficients.from_yaml(_BASE_COEFFICIENTS_PATH)
    best_params = {
        "combiner.finding_evidence": 0.42,
        "combiner.security_path": 0.15,
        "combiner.taint": 0.18,
        "combiner.context": 0.25,
        "edge_type_weights.flows_to": 0.88,
        "sanitizer_bypass_bonus": 0.30,
    }

    merged = coefficients_from_best_params(best_params, base)

    assert merged.combiner.finding_evidence == 0.42
    assert merged.combiner.security_path == 0.15
    assert merged.combiner.taint == 0.18
    assert merged.combiner.context == 0.25
    assert merged.edge_type_weights.flows_to == 0.88
    assert merged.sanitizer_bypass_bonus == 0.30


def test_coefficients_from_best_params_preserves_untouched_sections() -> None:
    """Fields absent from best_params keep their base values."""

    base = RankingCoefficients.from_yaml(_BASE_COEFFICIENTS_PATH)
    best_params = {"combiner.finding_evidence": 0.5}

    merged = coefficients_from_best_params(best_params, base)

    assert merged.combiner.finding_evidence == 0.5
    assert merged.combiner.security_path == base.combiner.security_path
    assert merged.edge_type_weights == base.edge_type_weights
    assert merged.security_path_breakdown == base.security_path_breakdown


def test_coefficients_from_best_params_round_trips_through_yaml(tmp_path: Path) -> None:
    """The merged coefficients should serialize and reload identically."""

    base = RankingCoefficients.from_yaml(_BASE_COEFFICIENTS_PATH)
    best_params = {
        "combiner.taint": 0.27,
        "edge_decay_rates.calls": 0.71,
        "sanitizer_presence_damp": 0.55,
    }

    merged = coefficients_from_best_params(best_params, base)
    out = tmp_path / "tuned.yaml"
    merged.to_yaml(out)

    reloaded = RankingCoefficients.from_yaml(out)
    assert reloaded == merged


def test_budgeted_config_from_best_params_validates_flat_keys() -> None:
    """BudgetedRankingConfig has no nested sections; best_params map directly."""

    best_params = {
        "depth_decay": 0.55,
        "context_strength": 0.30,
        "role_prior_temperature": 1.20,
        "finding_evidence_scale": 1.10,
        "taint_evidence_scale": 0.90,
        "cpg_role_evidence_scale": 1.05,
        "lexical_fallback_cap": 0.45,
        "token_cost_power": 0.40,
        "novelty_penalty": 0.25,
        "role_coverage_bonus": 0.15,
        "small_node_token_threshold": 240,
        "local_window_radius": 3,
        "budget_safety_ratio": 0.92,
    }

    config = budgeted_config_from_best_params(best_params)

    assert config.depth_decay == 0.55
    assert config.small_node_token_threshold == 240
    assert config.local_window_radius == 3
    assert config.budget_safety_ratio == 0.92


def test_budgeted_config_from_best_params_falls_back_to_defaults_for_missing_keys() -> None:
    """Fields absent from best_params keep BudgetedRankingConfig defaults."""

    config = budgeted_config_from_best_params({"depth_decay": 0.50})

    assert config.depth_decay == 0.50
    assert config.budget_safety_ratio == BudgetedRankingConfig().budget_safety_ratio
    assert config.role_coverage_bonus == BudgetedRankingConfig().role_coverage_bonus


def test_suggest_multiplicative_boost_coefficients_perturbs_relevant_fields_only() -> None:
    """multiplicative_boost sampler must touch the boost lever + breakdown weights.

    It must NOT touch the cpg_structural-only knobs (combiner, edge_*,
    sanitizer_*) — those are inherited from the base coefficients unchanged.
    """

    base = RankingCoefficients.from_yaml(_BASE_COEFFICIENTS_PATH)
    trial = optuna.trial.FixedTrial(
        {
            "security_boost_weight": 1.75,
            "context_breakdown.depth": 0.55,
            "context_breakdown.structure": 0.20,
            "context_breakdown.file_prior": 0.25,
            "finding_evidence_breakdown.severity": 0.50,
            "finding_evidence_breakdown.confidence": 0.30,
            "finding_evidence_breakdown.agreement": 0.20,
            "security_path_breakdown.sink": 0.30,
            "security_path_breakdown.source": 0.20,
            "security_path_breakdown.guard": 0.15,
            "security_path_breakdown.path_evidence": 0.35,
            "security_path_breakdown.high_risk_cwe_evidence_base": 0.70,
            "structure_breakdown.render_kind": 0.15,
            "structure_breakdown.repeat_bonus": 0.85,
            "file_prior_breakdown.same_file": 0.60,
            "file_prior_breakdown.same_module": 0.30,
            "file_prior_breakdown.generated_penalty": 0.20,
        }
    )

    sampled = suggest_multiplicative_boost_coefficients(trial, base)

    # Tuned levers.
    assert sampled.security_boost_weight == 1.75
    assert sampled.context_breakdown.depth == 0.55
    assert sampled.structure_breakdown.repeat_bonus == 0.85
    assert sampled.security_path_breakdown.high_risk_cwe_evidence_base == 0.70

    # Out-of-scope sections come straight from the base.
    assert sampled.combiner == base.combiner
    assert sampled.edge_type_weights == base.edge_type_weights
    assert sampled.edge_decay_rates == base.edge_decay_rates
    assert sampled.sanitizer_bypass_bonus == base.sanitizer_bypass_bonus
    assert sampled.sanitizer_presence_damp == base.sanitizer_presence_damp


def test_coefficients_from_best_params_round_trips_multiplicative_boost_keys(
    tmp_path: Path,
) -> None:
    """The export helper must also handle a study tuned for multiplicative_boost."""

    base = RankingCoefficients.from_yaml(_BASE_COEFFICIENTS_PATH)
    best_params = {
        "security_boost_weight": 2.10,
        "context_breakdown.depth": 0.45,
        "finding_evidence_breakdown.severity": 0.55,
    }

    merged = coefficients_from_best_params(best_params, base)
    out = tmp_path / "tuned_mboost.yaml"
    merged.to_yaml(out)
    reloaded = RankingCoefficients.from_yaml(out)

    assert reloaded.security_boost_weight == 2.10
    assert reloaded.context_breakdown.depth == 0.45
    assert reloaded.finding_evidence_breakdown.severity == 0.55
    # Unmodified sections survive the round trip.
    assert reloaded.combiner == base.combiner
