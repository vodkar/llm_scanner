import logging
from pathlib import Path
from typing import Any

from cli import RankingStrategy
from clients.neo4j import Neo4jConfig
from models.benchmark.benchmark import BenchmarkDataset
from models.context_ranking import BudgetedRankingConfig
from services.analyzer.cleanvul_benchmark import CleanVulBenchmarkService
from services.benchmark.llm_judge import LLMJudgeService
from services.context_assembler.ranking_config import RankingCoefficients


def build_benchmark_and_score(
    coefficients: RankingCoefficients | BudgetedRankingConfig,
    *,
    strategy: RankingStrategy,
    dataset: Path,
    repo_cache_dir: Path,
    sample_count: int,
    seed: int,
    max_call_depth: int,
    judge: LLMJudgeService,
    work_dir: Path,
    delete_checkouts: bool = True,
) -> float:
    """Run the benchmark with `coefficients`, score it with the judge, return accuracy."""

    coeff_path = work_dir / "coefficients.yaml"
    coefficients.to_yaml(coeff_path)

    service = CleanVulBenchmarkService(
        dataset_path=dataset,
        output_dir=work_dir / "benchmarks",
        repo_cache_dir=repo_cache_dir,
        sample_count=sample_count,
        seed=seed,
        neo4j_config=Neo4jConfig(),
        max_call_depth=max_call_depth,
        token_budget=16384,
        cpg_structural_coefficients_path=(
            coeff_path if strategy == RankingStrategy.cpg_structural else None
        ),
        budgeted_ranking_config_path=(
            coeff_path if strategy == RankingStrategy.evidence_budgeted else None
        ),
        delete_checkouts=delete_checkouts,
    )
    dataset_paths, _entries = service.build_all_ranking_strategies()

    dataset_path = dataset_paths.get(strategy.value)
    if dataset_path is None or not dataset_path.exists():
        raise RuntimeError(f"strategy {strategy.value!r} produced no dataset file")

    benchmark_dataset = BenchmarkDataset.model_validate_json(
        dataset_path.read_text(encoding="utf-8")
    )
    result = judge.score_dataset(benchmark_dataset)
    logger = logging.getLogger(__name__)
    logger.info(
        "judge accuracy=%.4f invalid=%d samples=%d",
        result.accuracy,
        result.invalid_responses,
        len(benchmark_dataset.samples),
    )
    return result.accuracy


def suggest_budgeted_config(trial: optuna.Trial) -> BudgetedRankingConfig:
    """Sample a BudgetedRankingConfig over the full 14-parameter search space."""

    return BudgetedRankingConfig(
        depth_decay=trial.suggest_float("depth_decay", 0.25, 1.20),
        context_strength=trial.suggest_float("context_strength", 0.10, 0.75),
        role_prior_temperature=trial.suggest_float("role_prior_temperature", 0.60, 1.80),
        finding_evidence_scale=trial.suggest_float("finding_evidence_scale", 0.60, 1.50),
        taint_evidence_scale=trial.suggest_float("taint_evidence_scale", 0.60, 1.50),
        cpg_role_evidence_scale=trial.suggest_float("cpg_role_evidence_scale", 0.60, 1.50),
        lexical_fallback_cap=trial.suggest_float("lexical_fallback_cap", 0.20, 0.60),
        token_cost_power=trial.suggest_float("token_cost_power", 0.00, 0.80),
        novelty_penalty=trial.suggest_float("novelty_penalty", 0.00, 0.70),
        role_coverage_bonus=trial.suggest_float("role_coverage_bonus", 0.05, 0.40),
        small_node_token_threshold=trial.suggest_int(
            "small_node_token_threshold", 120, 420, step=20
        ),
        local_window_radius=trial.suggest_int("local_window_radius", 1, 6),
        budget_safety_ratio=trial.suggest_float("budget_safety_ratio", 0.85, 1.00),
    )


def suggest_coefficients(trial: optuna.Trial, base: RankingCoefficients) -> RankingCoefficients:
    """Sample a coefficients object by perturbing the base configuration."""

    payload: dict[str, Any] = base.model_dump()

    payload["combiner"] = {
        "finding_evidence": trial.suggest_float("combiner.finding_evidence", 0.1, 0.5),
        "security_path": trial.suggest_float("combiner.security_path", 0.1, 0.5),
        "taint": trial.suggest_float("combiner.taint", 0.1, 0.5),
        "context": trial.suggest_float("combiner.context", 0.1, 0.5),
    }
    payload["context_breakdown"] = {
        "depth": trial.suggest_float("context_breakdown.depth", 0.2, 0.8),
        "structure": trial.suggest_float("context_breakdown.structure", 0.05, 0.5),
        "file_prior": trial.suggest_float("context_breakdown.file_prior", 0.05, 0.5),
    }
    payload["edge_type_weights"] = {
        "flows_to": trial.suggest_float("edge_type_weights.flows_to", 0.6, 1.0),
        "sanitized_by": trial.suggest_float("edge_type_weights.sanitized_by", 0.5, 1.0),
        "calls": trial.suggest_float("edge_type_weights.calls", 0.3, 0.9),
        "called_by": trial.suggest_float("edge_type_weights.called_by", 0.3, 0.9),
        "defined_by": trial.suggest_float("edge_type_weights.defined_by", 0.3, 0.8),
        "used_by": trial.suggest_float("edge_type_weights.used_by", 0.2, 0.8),
        "contains": trial.suggest_float("edge_type_weights.contains", 0.1, 0.6),
    }
    payload["edge_decay_rates"] = {
        "flows_to": trial.suggest_float("edge_decay_rates.flows_to", 0.6, 0.95),
        "sanitized_by": trial.suggest_float("edge_decay_rates.sanitized_by", 0.6, 0.95),
        "calls": trial.suggest_float("edge_decay_rates.calls", 0.5, 0.9),
        "called_by": trial.suggest_float("edge_decay_rates.called_by", 0.5, 0.9),
        "defined_by": trial.suggest_float("edge_decay_rates.defined_by", 0.5, 0.9),
        "used_by": trial.suggest_float("edge_decay_rates.used_by", 0.5, 0.9),
        "contains": trial.suggest_float("edge_decay_rates.contains", 0.3, 0.8),
    }
    payload["sanitizer_bypass_bonus"] = trial.suggest_float("sanitizer_bypass_bonus", 0.0, 0.5)
    payload["sanitizer_presence_damp"] = trial.suggest_float("sanitizer_presence_damp", 0.0, 1.0)

    return RankingCoefficients.model_validate(payload)
