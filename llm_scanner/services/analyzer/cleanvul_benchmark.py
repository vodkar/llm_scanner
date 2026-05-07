import json
import logging
import shutil
import textwrap
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from clients.neo4j import Neo4jConfig, build_client
from models.benchmark.benchmark import (
    BenchmarkDataset,
    BenchmarkMetadata,
    BenchmarkSample,
    CleanVulSampleMetadata,
)
from models.benchmark.cleanvul import CleanVulEntry
from models.context import Context, FileSpans
from models.context_ranking import BudgetedRankingConfig
from pipeline import GeneralPipeline
from repositories.context import ContextRepository
from services.benchmark.cleanvul_loader import CleanVulLoaderService, CleanVulRow
from services.benchmark.repo_checkout import RepoCheckoutService
from services.context_assembler.context_assembler import ContextAssemblerService
from services.context_assembler.cpg_structural_ranking import CPGStructuralRankingStrategy
from services.context_assembler.evidence_ranking.strategy import (
    EvidenceAwareBudgetedNodeRankingStrategy,
)
from services.context_assembler.ranking import (
    ContextNodeRankingStrategy,
    DepthRepeatsContextNodeRankingStrategy,
    DummyNodeRankingStrategy,
    MultiplicativeBoostNodeRankingStrategy,
    NodeRelevanceRankingService,
    RandomNodeRankingStrategy,
)
from services.context_assembler.ranking_config import RankingCoefficients

logger = logging.getLogger(__name__)
LOGGING_INTERVAL = 10
CLEAR_DATABASE_QUERY: Final[str] = "MATCH (n) DETACH DELETE n"
CURRENT_STRATEGY_NAME: Final[str] = "current"

RankingStrategyFactory = Callable[[Path], ContextNodeRankingStrategy]
DatasetPathFactory = Callable[[str], Path]
MetadataNameFactory = Callable[[str], str]


class _CleanVulEntryPair(BaseModel):
    """Pair of vulnerable (func_before) and fixed (func_after) entries."""

    vulnerable_entry: CleanVulEntry
    fixed_entry: CleanVulEntry


class CleanVulBenchmarkService(BaseModel):
    """Build the CleanVul-with-context benchmark dataset."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    dataset_path: Path
    output_dir: Path
    repo_cache_dir: Path
    sample_count: int
    seed: int | None = None
    neo4j_config: Neo4jConfig = Field(default_factory=Neo4jConfig)
    max_call_depth: int = Field(ge=0, description="Maximum call graph depth for context assembly")
    token_budget: int = 8192
    delete_checkouts: bool = True
    min_score: int = Field(default=3, ge=0, le=4)
    python_only: bool = True
    exclude_test_files: bool = True
    cpg_structural_coefficients_path: Path | None = Field(
        default=None,
        description=(
            "Optional YAML path with coefficients for CPGStructuralRankingStrategy; "
            "when omitted, the strategy uses its own default coefficients."
        ),
    )
    budgeted_ranking_config_path: Path | None = Field(
        default=None,
        description=(
            "Optional YAML path with a BudgetedRankingConfig for "
            "EvidenceAwareBudgetedNodeRankingStrategy; when omitted, defaults are used."
        ),
    )

    def build(self) -> tuple[Path, Path]:
        """Generate the benchmark JSON files.

        Returns:
            Tuple of paths to the main dataset and entries files.
        """
        dataset_paths, entries_path = self._build_datasets(
            strategy_factories={CURRENT_STRATEGY_NAME: self._build_current_ranking_strategy}
        )
        return dataset_paths[CURRENT_STRATEGY_NAME], entries_path

    def build_all_ranking_strategies(self) -> tuple[dict[str, Path], Path]:
        """Generate aligned benchmark datasets for all available ranking strategies.

        Returns:
            Mapping of strategy names to dataset file paths and the entries file path.
        """
        return self._build_datasets(strategy_factories=self._build_strategy_factories())

    def _build_datasets(
        self,
        strategy_factories: Mapping[str, RankingStrategyFactory],
        dataset_path_factory: DatasetPathFactory | None = None,
        metadata_name_factory: MetadataNameFactory | None = None,
        sample_id_prefix: str = "CleanVulContextAssembler",
    ) -> tuple[dict[str, Path], Path]:
        """Build one or more datasets using the same accepted entry pairs.

        Also writes a companion entries file mapping each sample ID to its source
        CleanVulEntry so callers can associate CA benchmark samples back to the
        original function code and metadata.

        Args:
            strategy_factories: Ranking strategies to evaluate.
            dataset_path_factory: Optional dataset path resolver.
            metadata_name_factory: Optional metadata name resolver.
            sample_id_prefix: Prefix used for generated sample ids.

        Returns:
            Tuple of (strategy_name → dataset path, entries path).
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.repo_cache_dir.mkdir(parents=True, exist_ok=True)

        loader = CleanVulLoaderService(
            dataset_path=self.dataset_path,
            min_score=self.min_score,
            python_only=self.python_only,
            exclude_test_files=self.exclude_test_files,
        )
        candidate_rows = loader.fetch_entries()
        # rng = random.Random(self.seed)
        # rng.shuffle(candidate_rows)

        samples_by_strategy: dict[str, list[BenchmarkSample]] = {
            strategy_name: [] for strategy_name in strategy_factories
        }
        # Maps sample_id → CleanVulEntry (strategy-independent; written as companion file)
        entries_by_sample_id: dict[str, CleanVulEntry] = {}
        dataset_paths: dict[str, Path] = {}
        entries_path = self.output_dir / "cleanvul_entries.json"

        vulnerable_repo_service = RepoCheckoutService(cache_dir=self.repo_cache_dir / "vulnerable")
        fixed_repo_service = RepoCheckoutService(cache_dir=self.repo_cache_dir / "fixed")
        first_strategy_name = next(iter(strategy_factories))
        interrupted_error: KeyboardInterrupt | None = None

        try:
            for rows, repo_url, fix_hash in candidate_rows:
                current_sample_count = len(samples_by_strategy[first_strategy_name])
                if current_sample_count + 2 > self.sample_count:
                    break

                vulnerable_repo_path: Path | None = None
                fixed_repo_path: Path | None = None
                commit_url = rows[0].commit_url
                try:
                    try:
                        vulnerable_repo_path = vulnerable_repo_service.checkout_repo(
                            repo_url=repo_url,
                            fix_hash=fix_hash,
                            is_vulnerable=True,
                        )
                        fixed_repo_path = fixed_repo_service.checkout_repo(
                            repo_url=repo_url,
                            fix_hash=fix_hash,
                            is_vulnerable=False,
                        )
                    except Exception:
                        logger.exception("Failed to checkout %s at %s", repo_url, fix_hash)
                        continue

                    if current_sample_count % LOGGING_INTERVAL == 0:
                        logger.info(
                            "Processing sample %d/%d",
                            current_sample_count + 1,
                            self.sample_count,
                        )

                    # Resolve line spans by text-matching in the checked-out files
                    pair = self._build_entry_pair(
                        rows=rows,
                        repo_url=repo_url,
                        fix_hash=fix_hash,
                        vulnerable_repo_path=vulnerable_repo_path,
                        fixed_repo_path=fixed_repo_path,
                    )
                    if pair is None:
                        logger.warning(
                            "Could not build entry pair for %s; skipping this commit",
                            commit_url,
                        )
                        continue

                    budget_reason = self._entry_pair_budget_reason(pair)
                    if budget_reason is not None:
                        logger.warning(
                            "Skipping %s because source samples exceed budget or are unavailable",
                            commit_url,
                        )
                        continue

                    try:
                        vulnerable_contexts = self._scan_repository_for_entry(
                            repo_path=vulnerable_repo_path,
                            entry=pair.vulnerable_entry,
                            strategy_factories=strategy_factories,
                        )
                        fixed_contexts = self._scan_repository_for_entry(
                            repo_path=fixed_repo_path,
                            entry=pair.fixed_entry,
                            strategy_factories=strategy_factories,
                        )
                    except Exception:
                        logger.exception("Failed to scan repository for %s", commit_url)
                        continue

                    if not self._is_all_contexts_present(
                        vulnerable_contexts, fixed_contexts, strategy_factories
                    ):
                        logger.warning(
                            "No context found for %s in at least one strategy",
                            commit_url,
                        )
                        continue

                    vulnerable_sample_id = f"{sample_id_prefix}-{current_sample_count + 1}"
                    fixed_sample_id = f"{sample_id_prefix}-{current_sample_count + 2}"
                    entries_by_sample_id[vulnerable_sample_id] = pair.vulnerable_entry
                    entries_by_sample_id[fixed_sample_id] = pair.fixed_entry
                    for strategy_name in strategy_factories:
                        samples_by_strategy[strategy_name].append(
                            self._to_sample(
                                pair.vulnerable_entry,
                                vulnerable_contexts[strategy_name],
                                vulnerable_sample_id,
                            )
                        )
                        samples_by_strategy[strategy_name].append(
                            self._to_sample(
                                pair.fixed_entry,
                                fixed_contexts[strategy_name],
                                fixed_sample_id,
                            )
                        )
                except KeyboardInterrupt as error:
                    logger.warning(
                        "Interrupted while processing %s; writing partial datasets",
                        commit_url,
                    )
                    interrupted_error = error
                    break
                finally:
                    self._delete_checkout(vulnerable_repo_path)
                    self._delete_checkout(fixed_repo_path)
        finally:
            dataset_paths = self._write_datasets(
                samples_by_strategy=samples_by_strategy,
                metadata_name_factory=metadata_name_factory,
                dataset_path_factory=dataset_path_factory,
            )
            self._write_entries(entries_by_sample_id, entries_path)

        if interrupted_error is not None:
            raise interrupted_error

        return dataset_paths, entries_path

    def _build_entry_pair(
        self,
        rows: list[CleanVulRow],
        repo_url: str,
        fix_hash: str,
        vulnerable_repo_path: Path,
        fixed_repo_path: Path,
    ) -> _CleanVulEntryPair | None:
        """Locate function spans for all rows in a commit group and build an entry pair.

        Multiple rows from the same commit (different functions/files) are merged
        into a single pair so that all spans are processed together. Individual
        functions whose spans cannot be located are skipped; the pair is returned
        as long as at least one function span was resolved on each side.

        Args:
            rows: All CleanVul rows for a single commit.
            repo_url: Repository base URL.
            fix_hash: Fix commit SHA.
            vulnerable_repo_path: Checked-out parent (vulnerable) repo path.
            fixed_repo_path: Checked-out fix (fixed) repo path.

        Returns:
            Paired entries, or ``None`` if no spans could be located.
        """
        # Accumulate spans per file path for each side
        vuln_spans_by_file: dict[str, list[tuple[int, int]]] = {}
        fixed_spans_by_file: dict[str, list[tuple[int, int]]] = {}
        vuln_func_codes: list[str] = []
        fixed_func_codes: list[str] = []

        for row in rows:
            vuln_file = vulnerable_repo_path / row.file_name
            fixed_file = fixed_repo_path / row.file_name

            vuln_span = self._find_function_line_span(vuln_file, row.func_before)
            fixed_span = self._find_function_line_span(fixed_file, row.func_after)

            if vuln_span is None or fixed_span is None:
                logger.warning(
                    "Could not locate function in %s for commit %s (vuln=%s, fixed=%s); "
                    "skipping this function",
                    row.file_name,
                    row.commit_url,
                    vuln_span,
                    fixed_span,
                )
                continue

            vuln_spans_by_file.setdefault(row.file_name, []).append(vuln_span)
            fixed_spans_by_file.setdefault(row.file_name, []).append(fixed_span)
            vuln_func_codes.append(row.func_before)
            fixed_func_codes.append(row.func_after)

        if not vuln_spans_by_file or not fixed_spans_by_file:
            return None

        representative = rows[0]
        cwe_ids = CleanVulLoaderService._parse_cwe_ids(representative.cwe_id)

        def _make_files_spans(spans_by_file: dict[str, list[tuple[int, int]]]) -> list[FileSpans]:
            return [FileSpans(Path(fname), spans) for fname, spans in spans_by_file.items()]

        def _make_entry(func_codes: list[str], is_vulnerable: bool) -> CleanVulEntry:
            spans_by_file = vuln_spans_by_file if is_vulnerable else fixed_spans_by_file
            return CleanVulEntry(
                commit_url=representative.commit_url,
                repo_url=repo_url,
                fix_hash=fix_hash,
                file_name=representative.file_name,
                func_code="\n".join(func_codes),
                files_spans=_make_files_spans(spans_by_file),
                cve_id=representative.cve_id,
                cwe_id=cwe_ids[0] if cwe_ids else None,
                cwe_ids=cwe_ids,
                vulnerability_score=representative.vulnerability_score,
                commit_msg=representative.commit_msg,
                is_vulnerable=is_vulnerable,
            )

        return _CleanVulEntryPair(
            vulnerable_entry=_make_entry(vuln_func_codes, is_vulnerable=True),
            fixed_entry=_make_entry(fixed_func_codes, is_vulnerable=False),
        )

    @staticmethod
    def _find_function_line_span(
        file_path: Path,
        func_code: str,
    ) -> tuple[int, int] | None:
        """Locate ``func_code`` in a file by text matching.

        Tries three increasingly lenient matching strategies in order:

        1. Exact match (rstrip each line; skip blank file lines while scanning).
        2. Whitespace-normalised match (collapse all runs of whitespace).
        3. Dedented match (``textwrap.dedent`` the needle, then whitespace-normalise).

        Args:
            file_path: Path to the source file in the checked-out repository.
            func_code: Function source text from the dataset.

        Returns:
            1-based ``(start_line, end_line)`` tuple, or ``None`` if not found.
        """
        try:
            file_text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

        file_lines = file_text.splitlines()

        def _rstrip_needle(code: str) -> list[str]:
            return [ln.rstrip() for ln in code.splitlines() if ln.strip()]

        def _normalise(line: str) -> str:
            return " ".join(line.split())

        def _normalise_needle(code: str) -> list[str]:
            return [_normalise(ln) for ln in code.splitlines() if ln.strip()]

        def _search(
            needle_lines: list[str], transform: Callable[[str], str]
        ) -> tuple[int, int] | None:
            if not needle_lines:
                return None
            first = needle_lines[0]
            for i, file_line in enumerate(file_lines):
                if transform(file_line) != first:
                    continue
                # Candidate start at file line i
                candidate_end = i
                needle_idx = 1
                j = i + 1
                while needle_idx < len(needle_lines) and j < len(file_lines):
                    file_transformed = transform(file_lines[j])
                    if file_transformed == needle_lines[needle_idx]:
                        needle_idx += 1
                        candidate_end = j
                    elif file_transformed == "":
                        pass  # skip blank file lines not in needle
                    else:
                        break  # mismatch
                    j += 1
                if needle_idx == len(needle_lines):
                    return (i + 1, candidate_end + 1)  # 1-based
            return None

        # Tier 1: exact (rstrip)
        result = _search(_rstrip_needle(func_code), str.rstrip)
        if result is not None:
            return result

        # Tier 2: whitespace-normalised
        result = _search(_normalise_needle(func_code), _normalise)
        if result is not None:
            return result

        # Tier 3: dedented + whitespace-normalised
        dedented = textwrap.dedent(func_code)
        result = _search(_normalise_needle(dedented), _normalise)
        return result

    def _scan_repository_for_entry(
        self,
        repo_path: Path,
        entry: CleanVulEntry,
        strategy_factories: Mapping[str, RankingStrategyFactory],
    ) -> dict[str, Context]:
        with build_client(
            self.neo4j_config.uri,
            self.neo4j_config.user,
            self.neo4j_config.password,
        ) as neo4j_client:
            neo4j_client.run_write(CLEAR_DATABASE_QUERY)
            GeneralPipeline(src=repo_path, neo4j_client=neo4j_client).run()

            context_repository = ContextRepository(client=neo4j_client)
            contexts: dict[str, Context] = {}
            for strategy_name, factory in strategy_factories.items():
                context_service = ContextAssemblerService(
                    project_root=repo_path,
                    context_repository=context_repository,
                    max_call_depth=self.max_call_depth,
                    token_budget=self.token_budget,
                    ranking_strategy=factory(repo_path),
                )
                contexts[strategy_name] = context_service.assemble_for_spans(
                    repo_path,
                    entry.files_spans,
                )
            return contexts

    def _build_current_ranking_strategy(self, repo_path: Path) -> ContextNodeRankingStrategy:
        return NodeRelevanceRankingService(
            project_root=repo_path,
            snippet_cache_max_entries=10000,
        )

    def _build_cpg_structural_ranking_strategy(self, repo_path: Path) -> ContextNodeRankingStrategy:
        if self.cpg_structural_coefficients_path is not None:
            coefficients = RankingCoefficients.from_yaml(self.cpg_structural_coefficients_path)
            return CPGStructuralRankingStrategy(
                project_root=repo_path,
                snippet_cache_max_entries=10000,
                coefficients=coefficients,
            )
        return CPGStructuralRankingStrategy(
            project_root=repo_path,
            snippet_cache_max_entries=10000,
        )

    def _build_evidence_budgeted_ranking_strategy(
        self, repo_path: Path
    ) -> ContextNodeRankingStrategy:
        if self.budgeted_ranking_config_path is not None:
            config = BudgetedRankingConfig.from_yaml(self.budgeted_ranking_config_path)
        else:
            config = BudgetedRankingConfig()
        return EvidenceAwareBudgetedNodeRankingStrategy(
            project_root=repo_path,
            token_budget=self.token_budget,
            config=config,
        )

    def _build_strategy_factories(self) -> dict[str, RankingStrategyFactory]:
        return {
            CURRENT_STRATEGY_NAME: self._build_current_ranking_strategy,
            "depth_repeats_context": lambda repo_path: DepthRepeatsContextNodeRankingStrategy(
                project_root=repo_path,
                snippet_cache_max_entries=10000,
            ),
            "random_picking": lambda repo_path: RandomNodeRankingStrategy(
                project_root=repo_path,
                snippet_cache_max_entries=10000,
                random_seed=self.seed,
            ),
            "multiplicative_boost": lambda repo_path: MultiplicativeBoostNodeRankingStrategy(
                project_root=repo_path,
                snippet_cache_max_entries=10000,
            ),
            "cpg_structural": self._build_cpg_structural_ranking_strategy,
            "evidence_budgeted": self._build_evidence_budgeted_ranking_strategy,
            "dummy": lambda _repo_path: DummyNodeRankingStrategy(),
        }

    def _to_sample(
        self,
        entry: CleanVulEntry,
        context: Context,
        sample_id: str,
    ) -> BenchmarkSample:
        return BenchmarkSample(
            id=sample_id,
            code=context.context_text,
            label=int(entry.is_vulnerable),
            metadata=self._entry_metadata(entry),
            cwe_types=[f"CWE-{n}" for n in entry.cwe_ids],
            severity="unknown",
        )

    def _entry_metadata(self, entry: CleanVulEntry) -> CleanVulSampleMetadata:
        return CleanVulSampleMetadata(
            commit_url=entry.commit_url,
            description=entry.commit_msg,
            cwe_number=entry.cwe_id,
        )

    def _build_metadata(
        self,
        samples: list[BenchmarkSample],
        dataset_name: str,
    ) -> BenchmarkMetadata:
        distribution: dict[str, int] = {}
        for sample in samples:
            cwe_number = sample.metadata.cwe_number
            if cwe_number is None:
                continue
            key = f"CWE-{cwe_number}"
            distribution[key] = distribution.get(key, 0) + 1

        return BenchmarkMetadata(
            name=dataset_name,
            task_type="binary",
            total_samples=len(samples),
            cwe_distribution=distribution,
        )

    def _entry_pair_budget_reason(self, pair: _CleanVulEntryPair) -> str | None:
        if self._estimate_tokens(pair.vulnerable_entry.func_code) > self.token_budget:
            return "source_sample_exceeds_token_budget"
        if self._estimate_tokens(pair.fixed_entry.func_code) > self.token_budget:
            return "source_sample_exceeds_token_budget"
        return None

    @staticmethod
    def _is_all_contexts_present(
        vulnerable_contexts: dict[str, Context],
        fixed_contexts: dict[str, Context],
        strategy_factories: Mapping[str, RankingStrategyFactory],
    ) -> bool:
        for strategy_name in strategy_factories:
            vulnerable_context = vulnerable_contexts.get(strategy_name)
            fixed_context = fixed_contexts.get(strategy_name)
            if vulnerable_context is None or fixed_context is None:
                return False
            if not vulnerable_context.context_text or not fixed_context.context_text:
                return False
        return True

    def _dataset_path(
        self,
        strategy_name: str,
        dataset_path_factory: DatasetPathFactory | None = None,
    ) -> Path:
        if dataset_path_factory is not None:
            return dataset_path_factory(strategy_name)
        if strategy_name == CURRENT_STRATEGY_NAME:
            return self.output_dir / "cleanvul_context_benchmark.json"
        return self.output_dir / f"cleanvul_context_benchmark_{strategy_name}.json"

    @staticmethod
    def _metadata_name(
        strategy_name: str,
        metadata_name_factory: MetadataNameFactory | None = None,
    ) -> str:
        if metadata_name_factory is not None:
            return metadata_name_factory(strategy_name)
        return f"CleanVul-with-Context-Benchmark-{strategy_name}"

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return max(1, len(text) // 3) if text else 0

    def _write_datasets(
        self,
        samples_by_strategy: Mapping[str, list[BenchmarkSample]],
        metadata_name_factory: MetadataNameFactory | None = None,
        dataset_path_factory: DatasetPathFactory | None = None,
    ) -> dict[str, Path]:
        dataset_paths: dict[str, Path] = {}
        for strategy_name, samples in samples_by_strategy.items():
            dataset = BenchmarkDataset(
                metadata=self._build_metadata(
                    samples,
                    self._metadata_name(strategy_name, metadata_name_factory),
                ),
                samples=samples,
            )
            dataset_path = self._dataset_path(strategy_name, dataset_path_factory)
            self._write_json(dataset_path, dataset.model_dump(by_alias=True))
            dataset_paths[strategy_name] = dataset_path
        return dataset_paths

    def _delete_checkout(self, repo_path: Path | None) -> None:
        if not self.delete_checkouts or repo_path is None or not repo_path.exists():
            return
        shutil.rmtree(str(repo_path))

    @staticmethod
    def _write_entries(
        entries_by_sample_id: dict[str, CleanVulEntry],
        path: Path,
    ) -> None:
        """Write a companion entries file mapping sample IDs to their CleanVulEntry data.

        The file is a JSON array of objects, each containing a ``sample_id`` field
        alongside all scalar CleanVulEntry fields, so consumers can join benchmark
        samples back to their source function code and metadata without re-parsing
        the original dataset.

        Args:
            entries_by_sample_id: Mapping of sample ID to its CleanVulEntry.
            path: Output file path.
        """
        records = [
            {
                "sample_id": sample_id,
                "commit_url": entry.commit_url,
                "repo_url": entry.repo_url,
                "fix_hash": entry.fix_hash,
                "file_name": entry.file_name,
                "func_code": entry.func_code,
                "cve_id": entry.cve_id,
                "cwe_id": entry.cwe_id,
                "cwe_ids": entry.cwe_ids,
                "vulnerability_score": entry.vulnerability_score,
                "commit_msg": entry.commit_msg,
                "is_vulnerable": entry.is_vulnerable,
            }
            for sample_id, entry in entries_by_sample_id.items()
        ]
        CleanVulBenchmarkService._write_json(path, records)

    @staticmethod
    def _write_json(path: Path, payload: object) -> None:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, default=str) + "\n")
