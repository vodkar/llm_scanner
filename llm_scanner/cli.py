# flake8: noqa E402

import json
import logging
import sys
import tempfile
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from tempfile import gettempdir
from typing import Annotated, Any, Final

import optuna
import typer

from logging_utils import configure_logging
from services.context_assembler.evidence_ranking.utils import (
    build_benchmark_and_score,
    suggest_budgeted_config,
    suggest_coefficients,
)

# This project historically uses flat imports like `from clients...` with
# `PYTHONPATH=llm_scanner/`. When installed as a console script, that path is
# not present by default, so we add the package directory to sys.path.
_PACKAGE_DIR: Final[Path] = Path(__file__).resolve().parent
if str(_PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_DIR))

from clients.neo4j import Neo4jConfig, build_client
from clients.openai_compatible import DEFAULT_REPETITION_PENALTY, OpenAICompatibleClient
from models.base import NodeID
from models.context_ranking import BudgetedRankingConfig
from models.edges import RelationshipBase
from models.nodes import Node
from repositories.graph import GraphRepository
from services.analyzer.cleanvul_benchmark import CleanVulBenchmarkService
from services.benchmark.llm_judge import LLMJudgeService
from services.context_assembler.ranking_config import RankingCoefficients
from services.cpg_parser.ts_parser.cpg_builder import (
    CPGDirectoryBuilder,
    CPGFileBuilder,
)

app = typer.Typer(
    name="llm-scanner",
    add_completion=False,
    no_args_is_help=True,
    help="Unified CLI for generating and loading code property graphs.",
    pretty_exceptions_enable=False,
)

ROOT_DIR: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_TESTS_DIR: Final[Path] = ROOT_DIR / "tests"
DEFAULT_SAMPLE_FILE: Final[Path] = DEFAULT_TESTS_DIR / "sample.py"
DEFAULT_OUTPUT_FILE: Final[Path] = ROOT_DIR / "output.yaml"
DEFAULT_BENCHMARK_DIR: Final[Path] = ROOT_DIR / "data"
DEFAULT_REPO_CACHE_DIR: Final[Path] = Path(gettempdir()) / "cvefixes_repos"
DEFAULT_CLEANVUL_REPO_CACHE_DIR: Final[Path] = Path(gettempdir()) / "cleanvul_repos"
DEFAULT_STUDY_DIR: Final[Path] = ROOT_DIR / "data" / "tuning_runs"
DEFAULT_BASE_COEFFICIENTS: Final[Path] = (
    ROOT_DIR / "config" / "ranking_coefficients_cpg_structural.yaml"
)


class RankingStrategy(str, Enum):
    cpg_structural = "cpg_structural"
    current = "current"
    evidence_budgeted = "evidence_budgeted"


@app.callback()
def main(
    log_level: Annotated[
        str,
        typer.Option(
            "--log-level",
            help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
            envvar="LOG_LEVEL",
            show_default=True,
        ),
    ] = "INFO",
) -> None:
    """Initialize CLI-wide settings before executing a command."""

    configure_logging(log_level)


@app.command("load-sample")
def load_sample(
    sample_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the Python file to load into Neo4j.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_SAMPLE_FILE,
    neo4j_uri: Annotated[
        str,
        typer.Option(
            "--neo4j-uri",
            help="Neo4j bolt URI.",
            envvar="NEO4J_URI",
            show_default=True,
        ),
    ] = Neo4jConfig().uri,
    neo4j_user: Annotated[
        str,
        typer.Option(
            "--neo4j-user",
            help="Neo4j username.",
            envvar="NEO4J_USER",
            show_default=True,
        ),
    ] = Neo4jConfig().user,
    neo4j_password: Annotated[
        str,
        typer.Option(
            "--neo4j-password",
            help="Neo4j password.",
            envvar="NEO4J_PASSWORD",
            show_default=False,
        ),
    ] = Neo4jConfig().password,
) -> None:
    """Parse a single file and load its CPG into Neo4j.

    Args:
        sample_path: Path to the Python file to parse.
        neo4j_uri: Bolt URI of the target Neo4j instance.
        neo4j_user: Username for the Neo4j instance.
        neo4j_password: Password for the Neo4j instance.
    """
    nodes: dict[NodeID, Node]
    edges: list[RelationshipBase]
    resolved_path = sample_path.resolve()
    nodes, edges = CPGFileBuilder(path=resolved_path).build()

    with build_client(neo4j_uri, neo4j_user, neo4j_password) as client:
        loader = GraphRepository(client)
        loader.load(nodes, edges)

    typer.secho(
        f"Loaded {len(nodes)} nodes and {len(edges)} edges from {sample_path}",
        fg=typer.colors.GREEN,
    )


@app.command()
def load(
    dir_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the Python project to load into Neo4j.",
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_SAMPLE_FILE,
    neo4j_uri: Annotated[
        str,
        typer.Option(
            "--neo4j-uri",
            help="Neo4j bolt URI.",
            envvar="NEO4J_URI",
            show_default=True,
        ),
    ] = Neo4jConfig().uri,
    neo4j_user: Annotated[
        str,
        typer.Option(
            "--neo4j-user",
            help="Neo4j username.",
            envvar="NEO4J_USER",
            show_default=True,
        ),
    ] = Neo4jConfig().user,
    neo4j_password: Annotated[
        str,
        typer.Option(
            "--neo4j-password",
            help="Neo4j password.",
            envvar="NEO4J_PASSWORD",
            show_default=False,
        ),
    ] = Neo4jConfig().password,
):
    """Parse a project directory and load its CPG into Neo4j."""
    resolved_path = dir_path.resolve()
    result = CPGDirectoryBuilder(root=resolved_path).build()

    with build_client(neo4j_uri, neo4j_user, neo4j_password) as client:
        loader = GraphRepository(client)
        loader.load(*result)


# @app.command("run-pipeline")
# def run_pipeline(
#     src: Annotated[
#         Path,
#         typer.Argument(
#             help="Path to the project root to scan.",
#             exists=True,
#             file_okay=False,
#             dir_okay=True,
#             readable=True,
#             resolve_path=True,
#         ),
#     ],
# ) -> None:
#     """Run the full analysis pipeline against a project directory.

#     Args:
#         src: Project root to scan and load into Neo4j.
#     """
#     pipeline = GeneralPipeline(src=src)
#     pipeline.run()
#     typer.secho(f"Pipeline completed for {src}", fg=typer.colors.GREEN)


@app.command("build-cleanvul-benchmark")
def build_cleanvul_benchmark(
    dataset_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the CleanVul CSV or Parquet file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    sample_count: Annotated[
        int,
        typer.Option("-n", "--samples", help="Number of samples to generate."),
    ] = 50,
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            help="Directory to write benchmark JSON files.",
            file_okay=False,
            dir_okay=True,
            writable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_BENCHMARK_DIR,
    repo_cache_dir: Annotated[
        Path,
        typer.Option(
            "--repo-cache-dir",
            help="Directory to cache cloned repositories.",
            file_okay=False,
            dir_okay=True,
            writable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_CLEANVUL_REPO_CACHE_DIR,
    seed: Annotated[
        int | None,
        typer.Option("--seed", help="Random seed for sampling."),
    ] = None,
    max_call_depth: Annotated[
        int,
        typer.Option("--max-call-depth", help="Max call depth for context expansion."),
    ] = 3,
    token_budget: Annotated[
        int,
        typer.Option("--token-budget", help="Token budget for context assembly."),
    ] = 2048,
    min_score: Annotated[
        int,
        typer.Option(
            "--min-score",
            help="Minimum vulnerability_score to include (0-4; dataset authors recommend >=3).",
            min=0,
            max=4,
        ),
    ] = 3,
    python_only: Annotated[
        bool,
        typer.Option(
            "--python-only/--all-languages",
            help="Restrict to Python files only.",
        ),
    ] = True,
    exclude_test_files: Annotated[
        bool,
        typer.Option(
            "--exclude-tests/--include-tests",
            help="Exclude rows flagged as test files.",
        ),
    ] = True,
    neo4j_uri: Annotated[
        str,
        typer.Option(
            "--neo4j-uri",
            help="Neo4j bolt URI.",
            envvar="NEO4J_URI",
            show_default=True,
        ),
    ] = Neo4jConfig().uri,
    neo4j_user: Annotated[
        str,
        typer.Option(
            "--neo4j-user",
            help="Neo4j username.",
            envvar="NEO4J_USER",
            show_default=True,
        ),
    ] = Neo4jConfig().user,
    neo4j_password: Annotated[
        str,
        typer.Option(
            "--neo4j-password",
            help="Neo4j password.",
            envvar="NEO4J_PASSWORD",
            show_default=False,
        ),
    ] = Neo4jConfig().password,
) -> None:
    """Build the CleanVul-with-context benchmark dataset."""

    service = CleanVulBenchmarkService(
        dataset_path=dataset_path,
        output_dir=output_dir,
        repo_cache_dir=repo_cache_dir,
        sample_count=sample_count,
        seed=seed,
        neo4j_config=Neo4jConfig(uri=neo4j_uri, user=neo4j_user, password=neo4j_password),
        max_call_depth=max_call_depth,
        token_budget=token_budget,
        min_score=min_score,
        python_only=python_only,
        exclude_test_files=exclude_test_files,
    )
    main_path, entries_path = service.build()

    typer.secho(
        f"Wrote benchmark dataset to {main_path}, entries to {entries_path}",
        fg=typer.colors.GREEN,
    )


@app.command("build-cleanvul-benchmark-compare-rankings")
def build_cleanvul_benchmark_compare_rankings(
    dataset_path: Annotated[
        Path,
        typer.Argument(
            help="Path to the CleanVul CSV or Parquet file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    sample_count: Annotated[
        int,
        typer.Option("-n", "--samples", help="Number of samples to generate."),
    ] = 50,
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            help="Directory to write benchmark JSON files.",
            file_okay=False,
            dir_okay=True,
            writable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_BENCHMARK_DIR,
    repo_cache_dir: Annotated[
        Path,
        typer.Option(
            "--repo-cache-dir",
            help="Directory to cache cloned repositories.",
            file_okay=False,
            dir_okay=True,
            writable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_CLEANVUL_REPO_CACHE_DIR,
    seed: Annotated[
        int | None,
        typer.Option("--seed", help="Random seed for sampling."),
    ] = None,
    max_call_depth: Annotated[
        int,
        typer.Option("--max-call-depth", help="Max call depth for context expansion."),
    ] = 3,
    token_budget: Annotated[
        int,
        typer.Option("--token-budget", help="Token budget for context assembly."),
    ] = 2048,
    min_score: Annotated[
        int,
        typer.Option(
            "--min-score",
            help="Minimum vulnerability_score to include (0-4; dataset authors recommend >=3).",
            min=0,
            max=4,
        ),
    ] = 3,
    python_only: Annotated[
        bool,
        typer.Option(
            "--python-only/--all-languages",
            help="Restrict to Python files only.",
        ),
    ] = True,
    exclude_test_files: Annotated[
        bool,
        typer.Option(
            "--exclude-tests/--include-tests",
            help="Exclude rows flagged as test files.",
        ),
    ] = True,
    neo4j_uri: Annotated[
        str,
        typer.Option(
            "--neo4j-uri",
            help="Neo4j bolt URI.",
            envvar="NEO4J_URI",
            show_default=True,
        ),
    ] = Neo4jConfig().uri,
    neo4j_user: Annotated[
        str,
        typer.Option(
            "--neo4j-user",
            help="Neo4j username.",
            envvar="NEO4J_USER",
            show_default=True,
        ),
    ] = Neo4jConfig().user,
    neo4j_password: Annotated[
        str,
        typer.Option(
            "--neo4j-password",
            help="Neo4j password.",
            envvar="NEO4J_PASSWORD",
            show_default=False,
        ),
    ] = Neo4jConfig().password,
) -> None:
    """Build aligned CleanVul-with-context datasets for all ranking strategies."""

    service = CleanVulBenchmarkService(
        dataset_path=dataset_path,
        output_dir=output_dir,
        repo_cache_dir=repo_cache_dir,
        sample_count=sample_count,
        seed=seed,
        neo4j_config=Neo4jConfig(uri=neo4j_uri, user=neo4j_user, password=neo4j_password),
        max_call_depth=max_call_depth,
        token_budget=token_budget,
        min_score=min_score,
        python_only=python_only,
        exclude_test_files=exclude_test_files,
    )
    dataset_paths, entries_path = service.build_all_ranking_strategies()

    typer.secho(
        f"Wrote benchmark datasets to {dataset_paths}, entries to {entries_path}",
        fg=typer.colors.GREEN,
    )


@app.command("tune-ranking-coefficients")
def tune_ranking_coefficients(
    strategy: Annotated[
        RankingStrategy,
        typer.Option(
            "--strategy",
            help="Ranking strategy to tune.",
            case_sensitive=False,
        ),
    ],
    judge_model: Annotated[
        str,
        typer.Option("--judge-model", help="Model name served by the judge endpoint."),
    ],
    dataset: Annotated[
        Path,
        typer.Option(
            "--dataset",
            help="CleanVul CSV path used to build per-trial benchmarks.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            help="Directory for per-trial benchmark artifacts.",
            file_okay=False,
            dir_okay=True,
            writable=True,
            resolve_path=True,
        ),
    ],
    repo_cache_dir: Annotated[
        Path,
        typer.Option(
            "--repo-cache-dir",
            help="Directory to cache cloned repositories.",
            file_okay=False,
            dir_okay=True,
            writable=True,
            resolve_path=True,
        ),
    ],
    trials: Annotated[int, typer.Option("--trials", help="Number of Optuna trials.")] = 20,
    sample_count: Annotated[
        int, typer.Option("--sample-count", help="Benchmark samples per trial.")
    ] = 40,
    judge_base_url: Annotated[
        str,
        typer.Option("--judge-base-url", help="OpenAI-compatible judge endpoint."),
    ] = "http://localhost:8000/v1",
    judge_api_key: Annotated[
        str, typer.Option("--judge-api-key", help="API key for the judge endpoint.")
    ] = "not-needed",
    study_name: Annotated[
        str | None,
        typer.Option(
            "--study-name",
            help="Optuna study name; defaults to a UTC timestamp.",
        ),
    ] = None,
    base_coefficients: Annotated[
        Path,
        typer.Option(
            "--base-coefficients",
            help="Base RankingCoefficients YAML to perturb (ignored for evidence_budgeted).",
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_BASE_COEFFICIENTS,
    max_call_depth: Annotated[
        int, typer.Option("--max-call-depth", help="Max call depth for context expansion.")
    ] = 2,
    concurrency: Annotated[
        int, typer.Option("--concurrency", help="Concurrent judge requests.")
    ] = 8,
    judge_max_tokens: Annotated[
        int, typer.Option("--judge-max-tokens", help="Max response tokens per judge call.")
    ] = 2048,
    judge_timeout: Annotated[
        float, typer.Option("--judge-timeout", help="Judge request timeout, seconds.")
    ] = 600.0,
    judge_temperature: Annotated[
        float,
        typer.Option(
            "--judge-temperature",
            help="Sampling temperature for the judge (Qwen3 thinking recommends 0.6).",
        ),
    ] = 0.6,
    judge_top_p: Annotated[
        float,
        typer.Option(
            "--judge-top-p",
            help="Nucleus-sampling top-p (Qwen3 thinking recommends 0.95).",
        ),
    ] = 0.95,
    judge_repetition_penalty: Annotated[
        float,
        typer.Option(
            "--judge-repetition-penalty",
            help="Repetition penalty forwarded to vLLM via extra_body (1.0 disables).",
        ),
    ] = DEFAULT_REPETITION_PENALTY,
    judge_top_k: Annotated[
        int | None,
        typer.Option(
            "--judge-top-k",
            help="Top-k sampling forwarded to vLLM via extra_body (omit to use server default).",
        ),
    ] = None,
    judge_min_p: Annotated[
        float | None,
        typer.Option(
            "--judge-min-p",
            help="Min-p sampling forwarded to vLLM via extra_body (omit to use server default).",
        ),
    ] = None,
    judge_thinking: Annotated[
        bool,
        typer.Option(
            "--judge-thinking/--no-judge-thinking",
            help="Enable chat-template thinking for Qwen3-family judges.",
        ),
    ] = True,
    seed: Annotated[int, typer.Option("--seed", help="Optuna sampler seed.")] = 42,
    delete_checkouts: Annotated[
        bool,
        typer.Option(
            "--delete-checkouts/--keep-checkouts",
            help="Whether to delete cloned repositories after each trial.",
        ),
    ] = True,
) -> None:
    """Tune ranking coefficients with Optuna against an LLM judge."""

    base_coeff_obj: RankingCoefficients | None
    if strategy == RankingStrategy.evidence_budgeted:
        base_coeff_obj = None
    else:
        base_coeff_obj = RankingCoefficients.from_yaml(base_coefficients)

    extra_body: dict[str, Any] | None = (
        {"chat_template_kwargs": {"enable_thinking": True}} if judge_thinking else None
    )
    judge = LLMJudgeService(
        client=OpenAICompatibleClient(
            base_url=judge_base_url,
            api_key=judge_api_key,
            model=judge_model,
            timeout_seconds=judge_timeout,
            default_temperature=judge_temperature,
            default_top_p=judge_top_p,
            default_repetition_penalty=judge_repetition_penalty,
            default_top_k=judge_top_k,
            default_min_p=judge_min_p,
            extra_body=extra_body,
        ),
        concurrency=concurrency,
        max_response_tokens=judge_max_tokens,
    )

    DEFAULT_STUDY_DIR.mkdir(parents=True, exist_ok=True)
    resolved_study_name = study_name or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    storage_url = f"sqlite:///{DEFAULT_STUDY_DIR / f'{resolved_study_name}.db'}"

    study = optuna.create_study(
        direction="maximize",
        study_name=resolved_study_name,
        storage=storage_url,
        load_if_exists=True,
        sampler=optuna.samplers.TPESampler(seed=seed),
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(__name__)
    with tempfile.TemporaryDirectory(prefix="ranking_tune_") as tmp:
        tmp_root = Path(tmp)

        def objective(trial: optuna.Trial) -> float:
            coefficients: RankingCoefficients | BudgetedRankingConfig
            if strategy == RankingStrategy.evidence_budgeted:
                coefficients = suggest_budgeted_config(trial)
            else:
                if base_coeff_obj is None:
                    raise RuntimeError("base_coefficients must be provided for non-budgeted tuning")
                coefficients = suggest_coefficients(trial, base_coeff_obj)
            trial_dir = tmp_root / f"trial_{trial.number:04d}"
            trial_dir.mkdir()
            return build_benchmark_and_score(
                coefficients,
                strategy=strategy,
                dataset=dataset,
                repo_cache_dir=repo_cache_dir,
                sample_count=sample_count,
                seed=seed,
                max_call_depth=max_call_depth,
                judge=judge,
                work_dir=trial_dir,
                delete_checkouts=delete_checkouts,
            )

        study.optimize(objective, n_trials=trials, show_progress_bar=False)

    logger.info("best accuracy=%.4f", study.best_value)
    logger.info("best params=%s", json.dumps(study.best_params, indent=2))
    logger.info("study persisted to %s", storage_url)
    typer.secho(
        f"Best accuracy {study.best_value:.4f}; study persisted to {storage_url}",
        fg=typer.colors.GREEN,
    )


if __name__ == "__main__":
    app()
