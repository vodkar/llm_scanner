import logging
import shutil
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from clients.neo4j import Neo4jConfig, build_client
from models.base import NodeID
from models.benchmark.benchmark import (
    BenchmarkSample,
    CleanVulSampleMetadata,
)
from models.benchmark.cleanvul import CleanVulEntry
from models.context import CodeContextNode, Context, FileSpans
from pipeline import GeneralScannerPipeline
from repositories.context import ContextRepository
from services.benchmark.cleanvul_loader import CleanVulLoaderService, CleanVulRow
from services.benchmark.dataset_builder import (
    DatasetBuilderService,
    DatasetPathFactory,
    MetadataNameFactory,
)
from services.benchmark.prepared_sample import (
    PreparedSample,
    compute_sample_cache_key,
    load_prepared_sample,
    save_prepared_sample,
)
from services.benchmark.repo_checkout import RepoCheckoutService
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import ContextNodeRankingStrategy
from services.source_code import SourceCodeService

logger = logging.getLogger(__name__)
LOGGING_INTERVAL = 10
CLEAR_DATABASE_QUERY: Final[str] = "MATCH (n) DETACH DELETE n"

RankingStrategyFactory = Callable[[Path], ContextNodeRankingStrategy]


class _CleanVulEntryPair(BaseModel):
    """Pair of vulnerable (func_before) and fixed (func_after) entries."""

    vulnerable_entry: CleanVulEntry
    fixed_entry: CleanVulEntry


class _SharedContextInputs(NamedTuple):
    """Shared fetched inputs reused across ranking strategies."""

    root_ids: list[str]
    plain_context_nodes: list[CodeContextNode]
    edge_path_context_nodes: list[CodeContextNode]
    taint_scores: dict[NodeID, float]


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
    min_score: int = Field(default=4, ge=0, le=4)
    max_repo_size_bytes: int | None = Field(
        default=1024 * 1024 * 100,  # 100 MB
        ge=1,
        description=(
            "Optional upper bound for checked-out repository size in bytes. "
            "Repositories larger than this are skipped before scanning."
        ),
    )
    strategy_factories: Mapping[str, RankingStrategyFactory] = Field(
        ...,
        description=(
            "Mapping of strategy name to factory callable. The caller "
            "(typically the CLI) assembles this dict; the service stays "
            "agnostic of per-strategy configuration."
        ),
    )

    def build(self) -> tuple[Path, Path]:
        """Generate the benchmark JSON files.

        Requires ``strategy_factories`` to contain exactly one entry. Returns
        the single dataset path plus the entries path.
        """
        if len(self.strategy_factories) != 1:
            raise ValueError(
                "build() requires exactly one strategy_factories entry; "
                f"got {len(self.strategy_factories)}."
            )
        dataset_paths, entries_path = self._build_datasets(self.strategy_factories)
        return next(iter(dataset_paths.values())), entries_path

    def build_all_ranking_strategies(self) -> tuple[dict[str, Path], Path]:
        """Generate aligned benchmark datasets for all configured ranking strategies.

        Returns:
            Mapping of strategy names to dataset file paths and the entries file path.
        """
        return self._build_datasets(self.strategy_factories)

    def prepare_samples(
        self,
        cache_dir: Path,
        *,
        sample_id_prefix: str = "CleanVulContextAssembler",
    ) -> list[PreparedSample]:
        """Phase 1: prepare and cache one ``PreparedSample`` per accepted entry.

        For each accepted ``(vulnerable, fixed)`` CleanVul commit, this walks the
        same candidate-row loop as ``_build_datasets`` (so accept/skip decisions
        are identical) and produces two ``PreparedSample`` records — one per
        side. Records are persisted to ``cache_dir`` keyed by repo/commit/spans
        so reruns are free on cache hit.

        The method ignores ``self.delete_checkouts`` and always keeps the
        repos on disk: Phase 2 needs them for file reads during rendering.
        Callers are responsible for cleaning up the cache directory and any
        leftover checkouts at study teardown.
        """

        self.repo_cache_dir.mkdir(parents=True, exist_ok=True)
        cache_dir.mkdir(parents=True, exist_ok=True)

        loader_options = {"min_score": self.min_score}
        loader = CleanVulLoaderService(
            dataset_path=self.dataset_path,
            min_score=self.min_score,
        )
        candidate_rows = loader.fetch_entries()

        vulnerable_repo_service = RepoCheckoutService(cache_dir=self.repo_cache_dir / "vulnerable")
        fixed_repo_service = RepoCheckoutService(cache_dir=self.repo_cache_dir / "fixed")

        prepared: list[PreparedSample] = []
        for rows, repo_url, fix_hash in candidate_rows:
            if len(prepared) + 2 > self.sample_count:
                break

            commit_url = rows[0].commit_url
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

            repo_size_reason = self._repo_size_reason(vulnerable_repo_path, fixed_repo_path)
            if repo_size_reason is not None:
                logger.warning("Skipping %s because %s", commit_url, repo_size_reason)
                continue

            if len(prepared) % LOGGING_INTERVAL == 0:
                logger.info(
                    "Preparing sample %d/%d",
                    len(prepared) + 1,
                    self.sample_count,
                )

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

            vulnerable_sample_id = f"{sample_id_prefix}-{len(prepared) + 1}"
            fixed_sample_id = f"{sample_id_prefix}-{len(prepared) + 2}"

            try:
                vulnerable_prepared = self._prepare_one_side(
                    repo_path=vulnerable_repo_path,
                    entry=pair.vulnerable_entry,
                    sample_id=vulnerable_sample_id,
                    cache_dir=cache_dir,
                    loader_options=loader_options,
                )
                fixed_prepared = self._prepare_one_side(
                    repo_path=fixed_repo_path,
                    entry=pair.fixed_entry,
                    sample_id=fixed_sample_id,
                    cache_dir=cache_dir,
                    loader_options=loader_options,
                )
            except Exception:
                logger.exception("Failed to prepare sample for %s", commit_url)
                continue

            prepared.append(vulnerable_prepared)
            prepared.append(fixed_prepared)

        logger.info("Phase 1 produced %d prepared samples in %s", len(prepared), cache_dir)
        return prepared

    def _prepare_one_side(
        self,
        *,
        repo_path: Path,
        entry: CleanVulEntry,
        sample_id: str,
        cache_dir: Path,
        loader_options: Mapping[str, object],
    ) -> PreparedSample:
        """Build (or load from cache) a ``PreparedSample`` for one side."""

        cache_key = compute_sample_cache_key(
            repo_url=entry.repo_url,
            fix_hash=entry.fix_hash,
            is_vulnerable=entry.is_vulnerable,
            max_call_depth=self.max_call_depth,
            files_spans=entry.files_spans,
            loader_options=loader_options,
        )
        cached = load_prepared_sample(cache_dir, cache_key)
        if cached is not None:
            cached.repo_path = repo_path
            cached.sample_id = sample_id
            return cached

        head_resolver = RepoCheckoutService(cache_dir=repo_path.parent)
        target_hash = head_resolver.resolve_head_hash(repo_path)

        with build_client(
            self.neo4j_config.uri,
            self.neo4j_config.user,
            self.neo4j_config.password,
        ) as neo4j_client:
            neo4j_client.run_write(CLEAR_DATABASE_QUERY)
            GeneralScannerPipeline(src=repo_path, neo4j_client=neo4j_client).build_cpg()

            context_repository = ContextRepository(client=neo4j_client)
            strategies: dict[str, ContextNodeRankingStrategy] = {
                strategy_name: factory(repo_path)
                for strategy_name, factory in self.strategy_factories.items()
            }
            shared_inputs = self._prepare_shared_context_inputs(
                repo_path=repo_path,
                entry=entry,
                context_repository=context_repository,
                strategies=strategies,
                force_full_superset=True,
            )
            edge_node_ids = sorted(
                {n.identifier for n in shared_inputs.plain_context_nodes}
                | {n.identifier for n in shared_inputs.edge_path_context_nodes}
            )
            neighborhood_edges = context_repository.fetch_neighborhood_edges(
                [str(nid) for nid in edge_node_ids]
            )
            path_fill_edge_types = context_repository.path_fill_edge_types
            traversal_relationship_types = context_repository.traversal_relationship_types

        sample = PreparedSample(
            entry=entry,
            repo_path=repo_path,
            target_hash=target_hash,
            sample_id=sample_id,
            root_ids=shared_inputs.root_ids,
            plain_context_nodes=shared_inputs.plain_context_nodes,
            edge_path_context_nodes=shared_inputs.edge_path_context_nodes,
            taint_scores=shared_inputs.taint_scores,
            neighborhood_edges=neighborhood_edges,
            path_fill_edge_types=path_fill_edge_types,
            traversal_relationship_types=traversal_relationship_types,
            cache_key=cache_key,
        )
        save_prepared_sample(cache_dir, sample)
        return sample

    def build_all_from_prepared(
        self,
        prepared_samples: Sequence[PreparedSample],
        *,
        dataset_path_factory: DatasetPathFactory | None = None,
        metadata_name_factory: MetadataNameFactory | None = None,
    ) -> tuple[dict[str, Path], Path]:
        """Phase 2: render datasets from ``PreparedSample`` cache (no Neo4j).

        Uses ``self.strategy_factories`` exactly like ``_build_datasets`` and
        produces the same dataset files. Skips repo checkout, CPG parsing,
        Neo4j ingest, and DB clearing — only ranking + render runs here.
        """

        self.output_dir.mkdir(parents=True, exist_ok=True)
        strategy_factories = self.strategy_factories
        samples_by_strategy: dict[str, list[BenchmarkSample]] = {
            strategy_name: [] for strategy_name in strategy_factories
        }
        entries_by_sample_id: dict[str, CleanVulEntry] = {}
        entries_path = self.output_dir / "cleanvul_entries.json"

        # Phase 1 may have checked out many commits into the same shared cache
        # directory; by Phase 2 each repo holds whatever was last checked out.
        # Re-align the working tree per sample (skipping when already aligned)
        # so file reads in `_render_context` match the spans cached at Phase 1.
        checkout_helper = RepoCheckoutService(cache_dir=self.repo_cache_dir)
        currently_checked_out: dict[Path, str] = {}

        for prepared in prepared_samples:
            current_hash = currently_checked_out.get(prepared.repo_path)
            if current_hash != prepared.target_hash:
                checkout_helper.checkout_commit(prepared.repo_path, prepared.target_hash)
                currently_checked_out[prepared.repo_path] = prepared.target_hash

            strategies: dict[str, ContextNodeRankingStrategy] = {
                strategy_name: factory(prepared.repo_path)
                for strategy_name, factory in strategy_factories.items()
            }
            shared_inputs = _SharedContextInputs(
                root_ids=prepared.root_ids,
                plain_context_nodes=prepared.plain_context_nodes,
                edge_path_context_nodes=prepared.edge_path_context_nodes,
                taint_scores=prepared.taint_scores,
            )
            contexts = self._render_contexts_from_shared_inputs(
                repo_path=prepared.repo_path,
                context_repository=None,
                strategies=strategies,
                shared_inputs=shared_inputs,
                cached_neighborhood_edges=prepared.neighborhood_edges,
            )
            entries_by_sample_id[prepared.sample_id] = prepared.entry
            for strategy_name in strategy_factories:
                samples_by_strategy[strategy_name].append(
                    self._to_sample(
                        prepared.entry,
                        contexts[strategy_name],
                        prepared.sample_id,
                    )
                )

        dataset_builder = DatasetBuilderService(output_dir=self.output_dir)
        dataset_paths = dataset_builder.write_datasets(
            samples_by_strategy=samples_by_strategy,
            metadata_name_factory=metadata_name_factory,
            dataset_path_factory=dataset_path_factory,
        )
        self._write_entries(entries_by_sample_id, entries_path)
        return dataset_paths, entries_path

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

                    repo_size_reason = self._repo_size_reason(
                        vulnerable_repo_path,
                        fixed_repo_path,
                    )
                    if repo_size_reason is not None:
                        logger.warning("Skipping %s because %s", commit_url, repo_size_reason)
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
            dataset_builder = DatasetBuilderService(output_dir=self.output_dir)
            dataset_paths = dataset_builder.write_datasets(
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

            vuln_span = SourceCodeService.find_function_line_span(vuln_file, row.func_before)
            fixed_span = SourceCodeService.find_function_line_span(fixed_file, row.func_after)

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

        def _make_entry(func_codes: list[str], *, is_vulnerable: bool) -> CleanVulEntry:
            spans_by_file = vuln_spans_by_file if is_vulnerable else fixed_spans_by_file
            return CleanVulEntry(
                commit_url=representative.commit_url,
                repo_url=repo_url,
                fix_hash=fix_hash,
                file_name=representative.file_name,
                func_code="\n".join(func_codes),
                files_spans=[
                    FileSpans(Path(fname), spans) for fname, spans in spans_by_file.items()
                ],
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
            GeneralScannerPipeline(src=repo_path, neo4j_client=neo4j_client).build_cpg()

            context_repository = ContextRepository(client=neo4j_client)
            strategies: dict[str, ContextNodeRankingStrategy] = {
                strategy_name: factory(repo_path)
                for strategy_name, factory in strategy_factories.items()
            }
            shared_inputs = self._prepare_shared_context_inputs(
                repo_path=repo_path,
                entry=entry,
                context_repository=context_repository,
                strategies=strategies,
            )

            return self._render_contexts_from_shared_inputs(
                repo_path=repo_path,
                context_repository=context_repository,
                strategies=strategies,
                shared_inputs=shared_inputs,
            )

    def _prepare_shared_context_inputs(
        self,
        repo_path: Path,
        entry: CleanVulEntry,
        context_repository: ContextRepository,
        strategies: Mapping[str, ContextNodeRankingStrategy],
        *,
        force_full_superset: bool = False,
    ) -> _SharedContextInputs:
        """Fetch shared context inputs needed by the supplied strategies.

        When ``force_full_superset`` is True the method ignores the strategies'
        ``requires_edge_paths`` / ``requires_taint_scores`` flags and fetches
        every variant unconditionally. This is what Phase 1 of the tuner cache
        flow requires so a single ``PreparedSample`` can serve any strategy.
        """

        fetch_service = self._build_context_service(
            repo_path=repo_path,
            context_repository=context_repository,
            ranking_strategy=next(iter(strategies.values())),
        )

        root_ids = fetch_service.fetch_root_ids_for_spans(entry.files_spans)
        if force_full_superset:
            needs_plain_context_nodes = True
            needs_edge_path_context_nodes = True
            needs_taint_scores = True
        else:
            needs_plain_context_nodes = any(
                not strategy.requires_edge_paths for strategy in strategies.values()
            )
            needs_edge_path_context_nodes = any(
                strategy.requires_edge_paths for strategy in strategies.values()
            )
            needs_taint_scores = any(
                strategy.requires_taint_scores for strategy in strategies.values()
            )

        plain_context_nodes: list[CodeContextNode] = []
        if needs_plain_context_nodes:
            plain_context_nodes = fetch_service.fetch_context_nodes_for_root_ids(
                root_ids,
                requires_edge_paths=False,
            )

        edge_path_context_nodes: list[CodeContextNode] = []
        if needs_edge_path_context_nodes:
            edge_path_context_nodes = fetch_service.fetch_context_nodes_for_root_ids(
                root_ids,
                requires_edge_paths=True,
            )

        taint_scores: dict[NodeID, float] = {}
        if needs_taint_scores:
            taint_scores = fetch_service.fetch_taint_scores(root_ids)

        return _SharedContextInputs(
            root_ids=root_ids,
            plain_context_nodes=plain_context_nodes,
            edge_path_context_nodes=edge_path_context_nodes,
            taint_scores=taint_scores,
        )

    def _render_contexts_from_shared_inputs(
        self,
        repo_path: Path,
        context_repository: ContextRepository | None,
        strategies: Mapping[str, ContextNodeRankingStrategy],
        shared_inputs: _SharedContextInputs,
        *,
        cached_neighborhood_edges: list[tuple[NodeID, NodeID, str]] | None = None,
    ) -> dict[str, Context]:
        """Render one context per strategy using shared fetched inputs.

        Pass ``cached_neighborhood_edges`` (and ``context_repository=None``) to
        render from a ``PreparedSample`` cache without any Neo4j connection.
        """

        contexts: dict[str, Context] = {}
        for strategy_name, strategy in strategies.items():
            base_context_nodes = (
                shared_inputs.edge_path_context_nodes
                if strategy.requires_edge_paths
                else shared_inputs.plain_context_nodes
            )
            context_nodes = base_context_nodes
            if strategy.requires_taint_scores:
                context_nodes = ContextAssemblerService.apply_taint_scores(
                    base_context_nodes,
                    shared_inputs.taint_scores,
                )
            context_service = self._build_context_service(
                repo_path=repo_path,
                context_repository=context_repository,
                ranking_strategy=strategy,
                cached_neighborhood_edges=cached_neighborhood_edges,
            )
            contexts[strategy_name] = context_service.assemble_from_nodes(repo_path, context_nodes)

        return contexts

    def _build_context_service(
        self,
        repo_path: Path,
        context_repository: ContextRepository | None,
        ranking_strategy: ContextNodeRankingStrategy,
        *,
        cached_neighborhood_edges: list[tuple[NodeID, NodeID, str]] | None = None,
    ) -> ContextAssemblerService:
        """Build a context assembler with the current benchmark settings."""

        return ContextAssemblerService(
            project_root=repo_path,
            context_repository=context_repository,
            max_call_depth=self.max_call_depth,
            token_budget=self.token_budget,
            ranking_strategy=ranking_strategy,
            cached_neighborhood_edges=cached_neighborhood_edges,
        )

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

    def _entry_pair_budget_reason(self, pair: _CleanVulEntryPair) -> str | None:
        if self._estimate_tokens(pair.vulnerable_entry.func_code) > self.token_budget:
            return "source_sample_exceeds_token_budget"
        if self._estimate_tokens(pair.fixed_entry.func_code) > self.token_budget:
            return "source_sample_exceeds_token_budget"
        return None

    def _repo_size_reason(
        self,
        vulnerable_repo_path: Path,
        fixed_repo_path: Path,
    ) -> str | None:
        """Return a skip reason when a checked-out repository exceeds the size limit."""

        max_repo_size_bytes = self.max_repo_size_bytes
        if max_repo_size_bytes is None:
            return None

        vulnerable_repo_size = self._estimate_repo_size_bytes(
            vulnerable_repo_path,
            cutoff_bytes=max_repo_size_bytes,
        )
        if vulnerable_repo_size > max_repo_size_bytes:
            return (
                f"vulnerable_repository_exceeds_size_limit "
                f"({vulnerable_repo_size}>{max_repo_size_bytes} bytes)"
            )

        fixed_repo_size = self._estimate_repo_size_bytes(
            fixed_repo_path,
            cutoff_bytes=max_repo_size_bytes,
        )
        if fixed_repo_size > max_repo_size_bytes:
            return (
                f"fixed_repository_exceeds_size_limit "
                f"({fixed_repo_size}>{max_repo_size_bytes} bytes)"
            )

        return None

    @staticmethod
    def _estimate_repo_size_bytes(repo_path: Path, cutoff_bytes: int | None = None) -> int:
        """Estimate repository size in bytes, skipping `.git` and stopping at an optional cutoff."""

        total_size_bytes = 0
        for path in repo_path.rglob("*"):
            if ".git" in path.parts:
                continue
            if not path.is_file():
                continue
            try:
                total_size_bytes += path.stat().st_size
            except OSError:
                continue
            if cutoff_bytes is not None and total_size_bytes > cutoff_bytes:
                return total_size_bytes
        return total_size_bytes

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

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return max(1, len(text) // 3)

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
        DatasetBuilderService.write_json(path, records)
