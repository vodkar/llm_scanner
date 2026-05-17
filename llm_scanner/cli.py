# flake8: noqa E402

import json
import logging
import sys
import tempfile
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from tempfile import gettempdir
from typing import Annotated, Any, Final, Literal, LiteralString

import optuna
import typer

# This project historically uses flat imports like `from clients...` with
# `PYTHONPATH=llm_scanner/`. When installed as a console script, that path is
# not present by default, so we add the package directory to sys.path.
_PACKAGE_DIR: Final[Path] = Path(__file__).resolve().parent
if str(_PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_DIR))

from clients.neo4j import Neo4jConfig, build_client
from clients.openai_compatible import DEFAULT_REPETITION_PENALTY, OpenAICompatibleClient
from diff_parser import parse_unified_diff
from logging_utils import configure_logging
from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.context_ranking import BudgetedRankingConfig
from models.edges import RelationshipBase
from models.nodes import Node
from models.ranking_strategy import RankingStrategy
from models.scan import ScanReport
from pipeline import GeneralScannerPipeline
from repositories.graph import GraphRepository
from sarif_exporter import SARIFExporter
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService
from services.benchmark.llm_judge import LLMJudgeService
from services.cpg_parser.ts_parser.cpg_builder import (
    CPGDirectoryBuilder,
    CPGFileBuilder,
)
from services.llm_review import LLMCodeReviewService
from services.ranking.evidence_ranking.utils import (
    budgeted_config_from_best_params,
    build_benchmark_and_score_from_prepared,
    coefficients_from_best_params,
    suggest_budgeted_config,
    suggest_coefficients,
    suggest_current_coefficients,
    suggest_multiplicative_boost_coefficients,
)
from services.ranking.ranking_config import RankingCoefficients
from services.ranking.strategy_factory import (
    RankingStrategies,
    _build_current_ranking_strategy,
    build_strategy_factories,
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


@app.callback()
def main(
    ctx: typer.Context,
    log_level: Annotated[
        Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        typer.Option(
            "--log-level",
            help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
            envvar="LOG_LEVEL",
            show_default=True,
        ),
    ] = "INFO",
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
    """Initialize CLI-wide settings before executing a command."""

    configure_logging(log_level)
    ctx.ensure_object(dict)
    ctx.obj["neo4j"] = Neo4jConfig(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)


@app.command("load-sample")
def load_sample(
    ctx: typer.Context,
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
) -> None:
    """Parse a single file and load its CPG into Neo4j.

    Args:
        sample_path: Path to the Python file to parse.
    """
    nodes: dict[NodeID, Node]
    edges: list[RelationshipBase]
    resolved_path = sample_path.resolve()
    nodes, edges = CPGFileBuilder(path=resolved_path).build()
    neo4j_config: Neo4jConfig = ctx.obj["neo4j"]
    with build_client(neo4j_config.uri, neo4j_config.user, neo4j_config.password) as client:
        loader = GraphRepository(client)
        loader.load(nodes, edges)

    typer.secho(
        f"Loaded {len(nodes)} nodes and {len(edges)} edges from {sample_path}",
        fg=typer.colors.GREEN,
    )


@app.command()
def load(
    ctx: typer.Context,
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
) -> None:
    """Parse a project directory and load its CPG into Neo4j."""
    resolved_path = dir_path.resolve()
    result = CPGDirectoryBuilder(root=resolved_path).build()
    neo4j_config: Neo4jConfig = ctx.obj["neo4j"]
    with build_client(neo4j_config.uri, neo4j_config.user, neo4j_config.password) as client:
        loader = GraphRepository(client)
        loader.load(*result)


@app.command("scan")
def scan(  # noqa: C901
    ctx: typer.Context,
    src: Annotated[
        Path,
        typer.Argument(
            help="Path to the project root to scan.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ],
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            help="Scan mode: 'full' (all static findings) or 'diff' (changed lines only).",
            show_default=True,
        ),
    ] = "full",
    diff_file: Annotated[
        Path | None,
        typer.Option(
            "--diff-file",
            help="Path to a git unified diff file (diff mode only; omit to read from stdin).",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
    strategy: Annotated[
        RankingStrategy,
        typer.Option(
            "--strategy",
            help="Context ranking strategy.",
            case_sensitive=False,
        ),
    ] = RankingStrategy.CPG_STRUCTURAL,
    min_severity: Annotated[
        IssueSeverity,
        typer.Option(
            "--min-severity",
            help="Minimum Bandit severity to include (Dlint always included).",
            case_sensitive=False,
        ),
    ] = IssueSeverity.HIGH,
    llm_base_url: Annotated[
        str,
        typer.Option("--llm-base-url", help="OpenAI-compatible LLM endpoint base URL."),
    ] = "http://localhost:8000/v1",
    llm_model: Annotated[
        str,
        typer.Option("--llm-model", help="Model name to use for code review."),
    ] = "Qwen/Qwen2.5-7B-Instruct",
    llm_api_key: Annotated[
        str,
        typer.Option("--llm-api-key", help="API key for the LLM endpoint."),
    ] = "not-needed",
    llm_max_tokens: Annotated[
        int,
        typer.Option("--llm-max-tokens", help="Max response tokens per review request."),
    ] = 2048,
    llm_concurrency: Annotated[
        int,
        typer.Option("--llm-concurrency", help="Concurrent LLM review requests."),
    ] = 8,
    max_call_depth: Annotated[
        int,
        typer.Option("--max-call-depth", help="Max BFS depth for context neighborhood."),
    ] = 3,
    token_budget: Annotated[
        int,
        typer.Option("--token-budget", help="Token budget per assembled context."),
    ] = 2048,
    output_json: Annotated[
        Path | None,
        typer.Option(
            "--output-json",
            help="Write the JSON report to this path.",
            file_okay=True,
            dir_okay=False,
            writable=True,
            resolve_path=True,
        ),
    ] = None,
    output_sarif: Annotated[
        Path | None,
        typer.Option(
            "--output-sarif",
            help="Write a SARIF 2.1.0 report to this path.",
            file_okay=True,
            dir_okay=False,
            writable=True,
            resolve_path=True,
        ),
    ] = None,
    no_fail: Annotated[
        bool,
        typer.Option(
            "--no-fail",
            help="Exit 0 even when vulnerabilities are found (useful for reporting-only CI steps).",
        ),
    ] = False,
) -> None:
    """Run the LLM-assisted security scanner against a project directory.

    In **full** mode every static-analyzer finding that meets ``--min-severity``
    is assembled into a code context and sent to the LLM for review.

    In **diff** mode the diff supplied via ``--diff-file`` (or stdin) is parsed
    and only code nodes overlapping changed lines are reviewed.

    The command exits with a non-zero status code when vulnerabilities are found
    unless ``--no-fail`` is given.
    """
    if mode not in ("full", "diff"):
        raise typer.BadParameter(
            f"mode must be 'full' or 'diff', got {mode!r}", param_hint="--mode"
        )

    neo4j_config: Neo4jConfig = ctx.obj["neo4j"]
    strategy_factories = build_strategy_factories(
        token_budget=token_budget,
        only_strategies=[strategy.value],
    )
    strategy_factory = strategy_factories[strategy.value]

    llm_client = OpenAICompatibleClient(
        base_url=llm_base_url,
        api_key=llm_api_key,
        model=llm_model,
    )
    llm_review_service = LLMCodeReviewService(
        client=llm_client,
        concurrency=llm_concurrency,
        max_response_tokens=llm_max_tokens,
    )

    with build_client(neo4j_config.uri, neo4j_config.user, neo4j_config.password) as neo4j_client:
        pipeline = GeneralScannerPipeline(src=src, neo4j_client=neo4j_client)

        report: ScanReport
        if mode == "full":
            report = pipeline.run(
                strategy_factory=strategy_factory,
                strategy_name=strategy.value,
                llm_review_service=llm_review_service,
                max_call_depth=max_call_depth,
                token_budget=token_budget,
                min_severity=min_severity,
            )
        else:
            if diff_file is not None:
                diff_text = diff_file.read_text(encoding="utf-8")
            else:
                diff_text = sys.stdin.read()
            file_spans = parse_unified_diff(diff_text, repo_root=src)
            report = pipeline.run_diff(
                file_spans=file_spans,
                strategy_factory=strategy_factory,
                strategy_name=strategy.value,
                llm_review_service=llm_review_service,
                max_call_depth=max_call_depth,
                token_budget=token_budget,
            )

    typer.echo(
        f"Scanned {report.total_contexts_scanned} contexts; "
        f"{report.vulnerabilities_found} vulnerabilit{'y' if report.vulnerabilities_found == 1 else 'ies'} found."
    )
    for finding in report.findings:
        if finding.vulnerable:
            typer.secho(
                f"  VULN {finding.file_path}:{finding.line_start}-{finding.line_end}"
                f" [{finding.severity}] {finding.description or ''}",
                fg=typer.colors.RED,
            )

    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.secho(f"JSON report written to {output_json}", fg=typer.colors.GREEN)

    if output_sarif is not None:
        SARIFExporter().to_file(report, output_sarif)
        typer.secho(f"SARIF report written to {output_sarif}", fg=typer.colors.GREEN)

    if report.vulnerabilities_found > 0 and not no_fail:
        raise typer.Exit(code=1)


@app.command("build-cleanvul-benchmark")
def build_cleanvul_benchmark(
    ctx: typer.Context,
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
) -> None:
    """Build the CleanVul-with-context benchmark dataset."""

    neo4j_config: Neo4jConfig = ctx.obj["neo4j"]
    service = CleanVulBenchmarkService(
        dataset_path=dataset_path,
        output_dir=output_dir,
        repo_cache_dir=repo_cache_dir,
        sample_count=sample_count,
        seed=seed,
        neo4j_config=neo4j_config,
        max_call_depth=max_call_depth,
        token_budget=token_budget,
        strategy_factories={
            RankingStrategies.CURRENT: partial(
                _build_current_ranking_strategy, current_coefficients=None
            )
        },
    )
    main_path, entries_path = service.build()

    typer.secho(
        f"Wrote benchmark dataset to {main_path}, entries to {entries_path}",
        fg=typer.colors.GREEN,
    )


@app.command("build-cleanvul-benchmark-compare-rankings")
def build_cleanvul_benchmark_compare_rankings(
    ctx: typer.Context,
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
    cpg_structural_coefficients: Annotated[
        Path | None,
        typer.Option(
            "--cpg-structural-coefficients",
            help=(
                "Optional YAML with tuned RankingCoefficients for the "
                "cpg_structural strategy. Defaults to the strategy's built-in "
                "coefficients when omitted."
            ),
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
    budgeted_ranking_config: Annotated[
        Path | None,
        typer.Option(
            "--budgeted-ranking-config",
            help=(
                "Optional YAML with a tuned BudgetedRankingConfig for the "
                "evidence_budgeted strategy. Defaults to BudgetedRankingConfig() "
                "when omitted."
            ),
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
    multiplicative_boost_coefficients: Annotated[
        Path | None,
        typer.Option(
            "--multiplicative-boost-coefficients",
            help=(
                "Optional YAML with tuned RankingCoefficients for the "
                "multiplicative_boost strategy. Defaults to the strategy's "
                "built-in coefficients when omitted."
            ),
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
    current_coefficients: Annotated[
        Path | None,
        typer.Option(
            "--current-coefficients",
            help=(
                "Optional YAML with tuned RankingCoefficients for the "
                "current (NodeRelevanceRankingService) strategy. Defaults to "
                "the strategy's built-in coefficients when omitted."
            ),
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
) -> None:
    """Build aligned CleanVul-with-context datasets for all ranking strategies."""

    neo4j_config: Neo4jConfig = ctx.obj["neo4j"]
    strategy_factories = build_strategy_factories(
        token_budget=token_budget,
        seed=seed,
        cpg_structural_coefficients=cpg_structural_coefficients,
        budgeted_ranking_config_path=budgeted_ranking_config,
        multiplicative_boost_coefficients=multiplicative_boost_coefficients,
        current_coefficients=current_coefficients,
    )
    service = CleanVulBenchmarkService(
        dataset_path=dataset_path,
        output_dir=output_dir,
        repo_cache_dir=repo_cache_dir,
        sample_count=sample_count,
        seed=seed,
        neo4j_config=neo4j_config,
        max_call_depth=max_call_depth,
        token_budget=token_budget,
        strategy_factories=strategy_factories,
    )
    dataset_paths, entries_path = service.build_all_ranking_strategies()

    typer.secho(
        f"Wrote benchmark datasets to {dataset_paths}, entries to {entries_path}",
        fg=typer.colors.GREEN,
    )


@app.command("tune-ranking-coefficients")
def tune_ranking_coefficients(
    ctx: typer.Context,
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
) -> None:
    """Tune ranking coefficients with Optuna against an LLM judge."""

    base_coeff_obj: RankingCoefficients | None
    if strategy == RankingStrategy.EVIDENCE_BUDGETED:
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

    prepared_cache_dir = repo_cache_dir / "prepared_samples"
    logger.info(
        "Phase 1: preparing up to %d samples into %s (this is a one-time cost; "
        "subsequent trials will reuse the cache)",
        sample_count,
        prepared_cache_dir,
    )
    prep_factories = build_strategy_factories(
        token_budget=16384,
        seed=seed,
        only_strategies=[RankingStrategies.DUMMY],
    )
    prep_service = CleanVulBenchmarkService(
        dataset_path=dataset,
        output_dir=output_dir / "prep",
        repo_cache_dir=repo_cache_dir,
        sample_count=sample_count,
        seed=seed,
        neo4j_config=ctx.obj["neo4j"],
        max_call_depth=max_call_depth,
        token_budget=16384,
        strategy_factories=prep_factories,
        delete_checkouts=False,
    )
    prepared_samples = prep_service.prepare_samples(prepared_cache_dir)
    logger.info(
        "Phase 1 produced %d prepared samples; entering Optuna study with %d trials",
        len(prepared_samples),
        trials,
    )

    with tempfile.TemporaryDirectory(prefix="ranking_tune_") as tmp:
        tmp_root = Path(tmp)

        def objective(trial: optuna.Trial) -> float:
            coefficients: RankingCoefficients | BudgetedRankingConfig
            if strategy == RankingStrategy.EVIDENCE_BUDGETED:
                coefficients = suggest_budgeted_config(trial)
            elif strategy == RankingStrategy.MULTIPLICATIVE_BOOST:
                if base_coeff_obj is None:
                    raise RuntimeError("base_coefficients must be provided for non-budgeted tuning")
                coefficients = suggest_multiplicative_boost_coefficients(trial, base_coeff_obj)
            elif strategy == RankingStrategy.CURRENT:
                if base_coeff_obj is None:
                    raise RuntimeError("base_coefficients must be provided for non-budgeted tuning")
                coefficients = suggest_current_coefficients(trial, base_coeff_obj)
            else:
                if base_coeff_obj is None:
                    raise RuntimeError("base_coefficients must be provided for non-budgeted tuning")
                coefficients = suggest_coefficients(trial, base_coeff_obj)
            trial_dir = tmp_root / f"trial_{trial.number:04d}"
            trial_dir.mkdir()
            return build_benchmark_and_score_from_prepared(
                coefficients,
                strategy=strategy,
                prepared_samples=prepared_samples,
                dataset=dataset,
                repo_cache_dir=repo_cache_dir,
                seed=seed,
                max_call_depth=max_call_depth,
                judge=judge,
                work_dir=trial_dir,
            )

        study.optimize(objective, n_trials=trials, show_progress_bar=False)

    logger.info("best accuracy=%.4f", study.best_value)
    logger.info("best params=%s", json.dumps(study.best_params, indent=2))
    logger.info("study persisted to %s", storage_url)
    typer.secho(
        f"Best accuracy {study.best_value:.4f}; study persisted to {storage_url}",
        fg=typer.colors.GREEN,
    )


@app.command("export-best-coefficients")
def export_best_coefficients(
    strategy: Annotated[
        RankingStrategy,
        typer.Option(
            "--strategy",
            help="Ranking strategy whose tuned coefficients to export.",
            case_sensitive=False,
        ),
    ],
    study_name: Annotated[
        str,
        typer.Option(
            "--study-name",
            help="Optuna study name passed to tune-ranking-coefficients.",
        ),
    ],
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            help="Destination YAML path for the tuned coefficients.",
            file_okay=True,
            dir_okay=False,
            writable=True,
            resolve_path=True,
        ),
    ],
    base_coefficients: Annotated[
        Path,
        typer.Option(
            "--base-coefficients",
            help=(
                "Base RankingCoefficients YAML to merge tuned params onto "
                "(required for cpg_structural; ignored for evidence_budgeted)."
            ),
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_BASE_COEFFICIENTS,
    study_dir: Annotated[
        Path,
        typer.Option(
            "--study-dir",
            help="Directory containing the Optuna SQLite study DBs.",
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ] = DEFAULT_STUDY_DIR,
) -> None:
    """Materialize the best params of a tuning study as a ready-to-use YAML.

    Loads ``<study-dir>/<study-name>.db``, reads ``study.best_params``, merges
    onto the base coefficients (for ``cpg_structural`` and
    ``multiplicative_boost``) or builds a ``BudgetedRankingConfig`` directly
    (for ``evidence_budgeted``), and writes the result as YAML at
    ``--output``. The output is the same shape consumed by
    ``--cpg-structural-coefficients`` / ``--budgeted-ranking-config`` /
    ``--multiplicative-boost-coefficients`` on
    ``build-cleanvul-benchmark-compare-rankings``.
    """

    storage_url = f"sqlite:///{study_dir / f'{study_name}.db'}"
    study = optuna.load_study(study_name=study_name, storage=storage_url)
    best_params = study.best_params
    logger = logging.getLogger(__name__)
    logger.info(
        "loaded study %s (best accuracy=%.4f, %d params)",
        study_name,
        study.best_value,
        len(best_params),
    )

    if strategy == RankingStrategy.EVIDENCE_BUDGETED:
        config = budgeted_config_from_best_params(best_params)
        config.to_yaml(output)
    elif strategy in (
        RankingStrategy.CPG_STRUCTURAL,
        RankingStrategy.MULTIPLICATIVE_BOOST,
        RankingStrategy.CURRENT,
    ):
        base = RankingCoefficients.from_yaml(base_coefficients)
        coefficients = coefficients_from_best_params(best_params, base)
        coefficients.to_yaml(output)
    else:
        raise typer.BadParameter(
            f"strategy {strategy.value!r} has no tunable coefficients to export",
            param_hint="--strategy",
        )

    typer.secho(
        f"Wrote tuned coefficients for {strategy.value} to {output}",
        fg=typer.colors.GREEN,
    )


if __name__ == "__main__":
    app()
