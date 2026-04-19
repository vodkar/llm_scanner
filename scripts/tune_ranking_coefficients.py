"""Optuna tuner for ranking coefficients scored by an LLM judge.

Samples `RankingCoefficients` values, builds a small benchmark dataset with the
chosen ranking strategy, scores it against the ground truth via
`LLMJudgeService`, and uses that accuracy as the Optuna objective.

Example:

    uv run python scripts/tune_ranking_coefficients.py \\
        --strategy cpg_structural \\
        --trials 3 \\
        --sample-count 5 \\
        --judge-base-url http://localhost:8000/v1 \\
        --judge-model Qwen/Qwen2.5-7B-Instruct \\
        --study-name smoke
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import optuna

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
_SRC_ROOT: Final[Path] = _REPO_ROOT / "llm_scanner"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from clients.neo4j import Neo4jConfig  # noqa: E402
from clients.openai_compatible import OpenAICompatibleClient  # noqa: E402
from models.benchmark.benchmark import BenchmarkDataset  # noqa: E402
from services.analyzer.cleanvul_benchmark import CleanVulBenchmarkService  # noqa: E402
from services.benchmark.llm_judge import LLMJudgeService  # noqa: E402
from services.context_assembler.ranking_config import RankingCoefficients  # noqa: E402

_LOGGER: Final[logging.Logger] = logging.getLogger("tune_ranking_coefficients")

_DEFAULT_STUDY_DIR: Final[Path] = _REPO_ROOT / "data" / "tuning_runs"

_SUPPORTED_STRATEGIES: Final[tuple[str, ...]] = ("cpg_structural", "current")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strategy", choices=_SUPPORTED_STRATEGIES, required=True)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--sample-count", type=int, default=40)
    parser.add_argument("--judge-base-url", type=str, default="http://localhost:8000/v1")
    parser.add_argument("--judge-model", type=str, required=True)
    parser.add_argument("--judge-api-key", type=str, default="not-needed")
    parser.add_argument("--study-name", type=str, default=None)
    parser.add_argument(
        "--base-coefficients",
        type=Path,
        default=_REPO_ROOT / "config" / "ranking_coefficients_cpg_structural.yaml",
    )
    parser.add_argument("--dataset", type=Path, required=True, help="CleanVul CSV path")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repo-cache-dir", type=Path, required=True)
    parser.add_argument("--max-call-depth", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def _suggest_coefficients(
    trial: optuna.Trial, base: RankingCoefficients
) -> RankingCoefficients:
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


def _build_benchmark_and_score(
    coefficients: RankingCoefficients,
    args: argparse.Namespace,
    judge: LLMJudgeService,
    work_dir: Path,
) -> float:
    """Run the benchmark with `coefficients`, score it with the judge, return accuracy."""

    coeff_path = work_dir / "coefficients.yaml"
    coefficients.to_yaml(coeff_path)

    service = CleanVulBenchmarkService(
        dataset_path=args.dataset,
        output_dir=work_dir / "benchmarks",
        repo_cache_dir=args.repo_cache_dir,
        sample_count=args.sample_count,
        seed=args.seed,
        neo4j_config=Neo4jConfig(),
        max_call_depth=args.max_call_depth,
        cpg_structural_coefficients_path=coeff_path
        if args.strategy == "cpg_structural"
        else None,
    )
    dataset_paths, _unassociated, _entries = service.build_all_ranking_strategies()

    dataset_path = dataset_paths.get(args.strategy)
    if dataset_path is None or not dataset_path.exists():
        raise RuntimeError(f"strategy {args.strategy!r} produced no dataset file")

    dataset = BenchmarkDataset.model_validate_json(dataset_path.read_text(encoding="utf-8"))
    result = judge.score_dataset(dataset)
    _LOGGER.info(
        "judge accuracy=%.4f invalid=%d samples=%d",
        result.accuracy,
        result.invalid_responses,
        len(dataset.samples),
    )
    return result.accuracy


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    args = _parse_args()

    base_coefficients = RankingCoefficients.from_yaml(args.base_coefficients)
    judge = LLMJudgeService(
        client=OpenAICompatibleClient(
            base_url=args.judge_base_url,
            api_key=args.judge_api_key,
            model=args.judge_model,
        ),
        concurrency=args.concurrency,
    )

    _DEFAULT_STUDY_DIR.mkdir(parents=True, exist_ok=True)
    study_name = args.study_name or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    storage_url = f"sqlite:///{_DEFAULT_STUDY_DIR / f'{study_name}.db'}"

    study = optuna.create_study(
        direction="maximize",
        study_name=study_name,
        storage=storage_url,
        load_if_exists=True,
        sampler=optuna.samplers.TPESampler(seed=args.seed),
    )

    with tempfile.TemporaryDirectory(prefix="ranking_tune_") as tmp:
        tmp_root = Path(tmp)

        def objective(trial: optuna.Trial) -> float:
            coefficients = _suggest_coefficients(trial, base_coefficients)
            trial_dir = tmp_root / f"trial_{trial.number:04d}"
            trial_dir.mkdir()
            return _build_benchmark_and_score(coefficients, args, judge, trial_dir)

        study.optimize(objective, n_trials=args.trials, show_progress_bar=False)

    _LOGGER.info("best accuracy=%.4f", study.best_value)
    _LOGGER.info("best params=%s", json.dumps(study.best_params, indent=2))
    _LOGGER.info("study persisted to %s", storage_url)


if __name__ == "__main__":
    main()
