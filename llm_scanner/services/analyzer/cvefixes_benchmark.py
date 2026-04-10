from __future__ import annotations

import json
import logging
import random
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from clients.neo4j import Neo4jConfig, build_client
from models.benchmark.benchmark import (
    BenchmarkDataset,
    BenchmarkMetadata,
    BenchmarkSample,
    BenchmarkSampleMetadata,
    UnassociatedSample,
)
from models.benchmark.cvefixes import CVEFixesEntry
from models.context import Context
from pipeline import GeneralPipeline
from repositories.context import ContextRepository
from services.benchmark.cvefixes_loader import CVEFixesLoaderService
from services.benchmark.repo_checkout import RepoCheckoutService
from services.context_assembler.context_assembler import ContextAssemblerService
from services.context_assembler.ranking import (
    ContextNodeRankingStrategy,
    DepthRepeatsContextNodeRankingStrategy,
    DummyNodeRankingStrategy,
    MultiplicativeBoostNodeRankingStrategy,
    NodeRelevanceRankingService,
    RandomNodeRankingStrategy,
)

logger = logging.getLogger(__name__)
LOGGING_INTERVAL = 10
CLEAR_DATABASE_QUERY: Final[str] = "MATCH (n) DETACH DELETE n"
CURRENT_STRATEGY_NAME: Final[str] = "current"
DEPTH_SWEEP_SIZES: Final[tuple[int, ...]] = (2, 3, 4, 5, 6)

RankingStrategyFactory = Callable[[Path], ContextNodeRankingStrategy]
DatasetPathFactory = Callable[[str], Path]
MetadataNameFactory = Callable[[str], str]


class _CVEFixesEntryPair(BaseModel):
    """Pair vulnerable and fixed benchmark entries for one CVE fix."""

    vulnerable_entry: CVEFixesEntry
    fixed_entry: CVEFixesEntry


class CVEFixesBenchmarkService(BaseModel):
    """Build the CVEFixes-with-context benchmark dataset."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    db_path: Path
    output_dir: Path
    repo_cache_dir: Path
    sample_count: int
    seed: int | None = None
    neo4j_config: Neo4jConfig = Field(default_factory=Neo4jConfig)
    max_call_depth: int = Field(ge=0, description="Maximum call graph depth for context assembly")
    token_budget: int = 8192
    delete_checkouts: bool = True

    def build(self) -> tuple[Path, Path]:
        """Generate the benchmark JSON files.

        Returns:
            Tuple of paths to the main dataset and unassociated dataset files.
        """

        dataset_paths, unassociated_path = self._build_datasets(
            strategy_factories={CURRENT_STRATEGY_NAME: self._build_current_ranking_strategy}
        )
        return dataset_paths[CURRENT_STRATEGY_NAME], unassociated_path

    def build_all_ranking_strategies(self) -> tuple[dict[str, Path], Path]:
        """Generate aligned benchmark datasets for all available ranking strategies.

        Returns:
            Mapping of strategy names to dataset file paths and the unassociated file path.
        """

        return self._build_datasets(strategy_factories=self._build_strategy_factories())

    def build_all_depth_sizes(self) -> tuple[dict[int, Path], dict[int, Path]]:
        """Generate benchmark datasets for a fixed ranking strategy across call depths.

        Returns:
            Dataset paths and unassociated paths keyed by max call depth.
        """

        dataset_paths_by_depth: dict[int, Path] = {}
        unassociated_paths_by_depth: dict[int, Path] = {}
        strategy_factories: dict[str, RankingStrategyFactory] = {
            CURRENT_STRATEGY_NAME: self._build_current_ranking_strategy
        }

        for max_call_depth in DEPTH_SWEEP_SIZES:
            dataset_paths, unassociated_path = self._build_datasets(
                strategy_factories=strategy_factories,
                max_call_depth=max_call_depth,
                dataset_path_factory=self._depth_dataset_path_factory(max_call_depth),
                metadata_name_factory=self._depth_metadata_name_factory(max_call_depth),
                unassociated_path=self._depth_unassociated_path(max_call_depth),
                sample_id_prefix=f"ContextAssemblerDepth{max_call_depth}",
            )
            dataset_paths_by_depth[max_call_depth] = dataset_paths[CURRENT_STRATEGY_NAME]
            unassociated_paths_by_depth[max_call_depth] = unassociated_path

        return dataset_paths_by_depth, unassociated_paths_by_depth

    def _build_datasets(
        self,
        strategy_factories: Mapping[str, RankingStrategyFactory],
        max_call_depth: int | None = None,
        dataset_path_factory: DatasetPathFactory | None = None,
        metadata_name_factory: MetadataNameFactory | None = None,
        unassociated_path: Path | None = None,
        sample_id_prefix: str = "ContextAssembler",
    ) -> tuple[dict[str, Path], Path]:
        """Build one or more datasets using the same accepted entry pairs.

        Args:
            strategy_factories: Ranking strategies to evaluate.
            max_call_depth: Optional max traversal depth override.
            dataset_path_factory: Optional dataset path resolver.
            metadata_name_factory: Optional metadata name resolver.
            unassociated_path: Optional unassociated output path.
            sample_id_prefix: Prefix used for generated sample ids.

        Returns:
            Mapping of strategy names to dataset file paths and the unassociated file path.
        """

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.repo_cache_dir.mkdir(parents=True, exist_ok=True)

        loader = CVEFixesLoaderService(db_path=self.db_path)
        candidate_pairs = self._pair_entries(loader.fetch_python_entries())
        rng = random.Random(self.seed)
        rng.shuffle(candidate_pairs)
        effective_max_call_depth = self.max_call_depth if max_call_depth is None else max_call_depth

        samples_by_strategy: dict[str, list[BenchmarkSample]] = {
            strategy_name: [] for strategy_name in strategy_factories
        }
        unassociated: list[UnassociatedSample] = []
        dataset_paths: dict[str, Path] = {}
        resolved_unassociated_path = (
            self.output_dir / "cvefixes_unassociated.json"
            if unassociated_path is None
            else unassociated_path
        )

        vulnerable_repo_service = RepoCheckoutService(cache_dir=self.repo_cache_dir / "vulnerable")
        fixed_repo_service = RepoCheckoutService(cache_dir=self.repo_cache_dir / "fixed")
        first_strategy_name = next(iter(strategy_factories))
        interrupted_error: KeyboardInterrupt | None = None

        try:
            for pair in candidate_pairs:
                current_sample_count = len(samples_by_strategy[first_strategy_name])
                if current_sample_count + 2 > self.sample_count:
                    break

                vulnerable_repo_path: Path | None = None
                fixed_repo_path: Path | None = None
                try:
                    try:
                        vulnerable_repo_path = vulnerable_repo_service.checkout_repo(
                            repo_url=pair.vulnerable_entry.repo_url,
                            fix_hash=pair.vulnerable_entry.fix_hash,
                            is_vulnerable=True,
                        )
                        fixed_repo_path = fixed_repo_service.checkout_repo(
                            repo_url=pair.fixed_entry.repo_url,
                            fix_hash=pair.fixed_entry.fix_hash,
                            is_vulnerable=False,
                        )
                    except Exception:
                        logger.exception(
                            "Failed to checkout %s at %s",
                            pair.vulnerable_entry.repo_url,
                            pair.vulnerable_entry.fix_hash,
                        )
                        self._append_unassociated_pair(unassociated, pair, reason="checkout_failed")
                        continue

                    if current_sample_count % LOGGING_INTERVAL == 0:
                        logger.info(
                            "Processing sample %d/%d",
                            current_sample_count + 1,
                            self.sample_count,
                        )

                    budget_reason = self._entry_pair_budget_reason(
                        vulnerable_repo_path=vulnerable_repo_path,
                        fixed_repo_path=fixed_repo_path,
                        pair=pair,
                    )
                    if budget_reason is not None:
                        logger.warning(
                            "Skipping %s because source samples exceed budget or are unavailable",
                            pair.vulnerable_entry.cve_id,
                        )
                        self._append_unassociated_pair(unassociated, pair, reason=budget_reason)
                        continue

                    try:
                        vulnerable_contexts = self._scan_repository_for_entry(
                            repo_path=vulnerable_repo_path,
                            entry=pair.vulnerable_entry,
                            strategy_factories=strategy_factories,
                            max_call_depth=effective_max_call_depth,
                        )
                        fixed_contexts = self._scan_repository_for_entry(
                            repo_path=fixed_repo_path,
                            entry=pair.fixed_entry,
                            strategy_factories=strategy_factories,
                            max_call_depth=effective_max_call_depth,
                        )
                    except Exception:
                        logger.exception("Failed to scan repository for %s", pair.vulnerable_entry.cve_id)
                        self._append_unassociated_pair(unassociated, pair, reason="scan_failed")
                        continue

                    if not self._all_contexts_present(
                        vulnerable_contexts,
                        fixed_contexts,
                        strategy_factories,
                    ):
                        logger.warning(
                            "No context found for %s in at least one strategy",
                            pair.vulnerable_entry.cve_id,
                        )
                        self._append_unassociated_pair(unassociated, pair, reason="missing_context")
                        continue

                    vulnerable_sample_id = f"{sample_id_prefix}-{current_sample_count + 1}"
                    fixed_sample_id = f"{sample_id_prefix}-{current_sample_count + 2}"
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
                        pair.vulnerable_entry.cve_id,
                    )
                    self._append_unassociated_pair(unassociated, pair, reason="interrupted")
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
            self._write_json(
                resolved_unassociated_path,
                [item.model_dump(by_alias=True) for item in unassociated],
            )

        if interrupted_error is not None:
            raise interrupted_error

        return dataset_paths, resolved_unassociated_path

    def _scan_repository_for_entry(
        self,
        repo_path: Path,
        entry: CVEFixesEntry,
        strategy_factories: Mapping[str, RankingStrategyFactory],
        max_call_depth: int,
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
                    max_call_depth=max_call_depth,
                    token_budget=self.token_budget,
                    ranking_strategy=factory(repo_path),
                )
                contexts[strategy_name] = context_service.assemble_for_spans(
                    repo_path,
                    entry.files_spans,
                )
            return contexts

    def _build_current_ranking_strategy(self, repo_path: Path) -> ContextNodeRankingStrategy:
        """Build the current ranking strategy instance.

        Args:
            repo_path: Repository root.

        Returns:
            Strategy instance.
        """

        return NodeRelevanceRankingService(
            project_root=repo_path,
            snippet_cache_max_entries=10000,
        )

    def _build_strategy_factories(self) -> dict[str, RankingStrategyFactory]:
        """Return all benchmark ranking strategies.

        Returns:
            Mapping of strategy names to constructors.
        """

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
            "dummy": lambda _repo_path: DummyNodeRankingStrategy(),
        }

    def _to_sample(
        self,
        entry: CVEFixesEntry,
        context: Context,
        sample_id: str,
    ) -> BenchmarkSample:
        return BenchmarkSample(
            id=sample_id,
            code=context.context_text,
            label=int(entry.is_vulnerable),
            metadata=self._entry_metadata(entry),
            cwe_types=[],
            severity=entry.severity or "unknown",
        )

    def _entry_metadata(self, entry: CVEFixesEntry) -> BenchmarkSampleMetadata:
        payload: dict[str, object] = {
            "CVEFixes-Number": entry.cve_id,
            "description": entry.description,
            "cwe_number": entry.cwe_id,
        }
        return BenchmarkSampleMetadata.model_validate(payload)

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

    def _pair_entries(self, entries: list[CVEFixesEntry]) -> list[_CVEFixesEntryPair]:
        """Pair vulnerable and fixed CVEFixes entries.

        Args:
            entries: Loaded CVEFixes entries.

        Returns:
            Pairs that have both vulnerable and fixed entries.
        """

        grouped_entries: dict[tuple[str, str, str], dict[bool, CVEFixesEntry]] = {}
        for entry in entries:
            pair_key = (entry.cve_id, entry.repo_url, entry.fix_hash)
            if pair_key not in grouped_entries:
                grouped_entries[pair_key] = {}
            grouped_entries[pair_key][entry.is_vulnerable] = entry

        pairs: list[_CVEFixesEntryPair] = []
        for pair_key in sorted(grouped_entries.keys()):
            entry_group = grouped_entries[pair_key]
            vulnerable_entry = entry_group.get(True)
            fixed_entry = entry_group.get(False)
            if vulnerable_entry is None or fixed_entry is None:
                continue
            pairs.append(
                _CVEFixesEntryPair(
                    vulnerable_entry=vulnerable_entry,
                    fixed_entry=fixed_entry,
                )
            )
        return pairs

    def _entry_pair_budget_reason(
        self,
        vulnerable_repo_path: Path,
        fixed_repo_path: Path,
        pair: _CVEFixesEntryPair,
    ) -> str | None:
        """Return skip reason when before/after source samples are not usable.

        Args:
            vulnerable_repo_path: Vulnerable checkout path.
            fixed_repo_path: Fixed checkout path.
            pair: Paired entries.

        Returns:
            Skip reason, or ``None`` when both source samples fit the token budget.
        """

        vulnerable_source = self._read_source_sample(vulnerable_repo_path, pair.vulnerable_entry)
        fixed_source = self._read_source_sample(fixed_repo_path, pair.fixed_entry)
        if vulnerable_source is None or fixed_source is None:
            return "source_sample_unavailable"
        if self._estimate_tokens(vulnerable_source) > self.token_budget:
            return "source_sample_exceeds_token_budget"
        if self._estimate_tokens(fixed_source) > self.token_budget:
            return "source_sample_exceeds_token_budget"
        return None

    def _read_source_sample(self, repo_path: Path, entry: CVEFixesEntry) -> str | None:
        """Read the before or after CVEFixes code sample for an entry.

        Args:
            repo_path: Checked-out repository root.
            entry: CVEFixes entry.

        Returns:
            Extracted source sample, or ``None`` when it cannot be read.
        """

        parts: list[str] = []
        for file_span in entry.files_spans:
            file_path = repo_path / file_span.file_path
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                return None

            for start_line, end_line in file_span.line_spans:
                if start_line < 1 or start_line > len(lines):
                    return None
                clipped_end = min(end_line, len(lines))
                parts.extend(lines[start_line - 1 : clipped_end])

        return "\n".join(parts)

    def _append_unassociated_pair(
        self,
        unassociated: list[UnassociatedSample],
        pair: _CVEFixesEntryPair,
        reason: str,
    ) -> None:
        """Append both vulnerable and fixed entries as unassociated.

        Args:
            unassociated: Existing unassociated entries.
            pair: Paired entries.
            reason: Reason for skipping the pair.
        """

        unassociated.append(
            UnassociatedSample(
                entry=self._entry_metadata(pair.vulnerable_entry),
                reason=reason,
                contexts=[],
            )
        )
        unassociated.append(
            UnassociatedSample(
                entry=self._entry_metadata(pair.fixed_entry),
                reason=reason,
                contexts=[],
            )
        )

    @staticmethod
    def _all_contexts_present(
        vulnerable_contexts: dict[str, Context],
        fixed_contexts: dict[str, Context],
        strategy_factories: Mapping[str, RankingStrategyFactory],
    ) -> bool:
        """Return whether all strategies produced non-empty contexts.

        Args:
            vulnerable_contexts: Vulnerable entry contexts by strategy.
            fixed_contexts: Fixed entry contexts by strategy.
            strategy_factories: Strategies expected to be present.

        Returns:
            Whether every strategy produced non-empty contexts for both entries.
        """

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
        """Return output path for a ranking strategy dataset."""

        if dataset_path_factory is not None:
            return dataset_path_factory(strategy_name)

        if strategy_name == CURRENT_STRATEGY_NAME:
            return self.output_dir / "cvefixes_context_benchmark.json"
        return self.output_dir / f"cvefixes_context_benchmark_{strategy_name}.json"

    @staticmethod
    def _metadata_name(
        strategy_name: str,
        metadata_name_factory: MetadataNameFactory | None = None,
    ) -> str:
        """Return metadata name for a dataset variant."""

        if metadata_name_factory is not None:
            return metadata_name_factory(strategy_name)
        return f"CVEFixes-with-Context-Benchmark-{strategy_name}"

    def _depth_dataset_path(self, max_call_depth: int) -> Path:
        """Return output path for a depth-sweep dataset."""

        return self.output_dir / f"cvefixes_context_benchmark_depth_{max_call_depth}.json"

    def _depth_unassociated_path(self, max_call_depth: int) -> Path:
        """Return output path for depth-sweep unassociated entries."""

        return self.output_dir / f"cvefixes_unassociated_depth_{max_call_depth}.json"

    def _depth_dataset_path_factory(self, max_call_depth: int) -> DatasetPathFactory:
        """Build a dataset path resolver for one max call depth."""

        def factory(_: str) -> Path:
            return self._depth_dataset_path(max_call_depth)

        return factory

    @staticmethod
    def _depth_metadata_name_factory(max_call_depth: int) -> MetadataNameFactory:
        """Build a metadata name resolver for one max call depth."""

        def factory(_: str) -> str:
            return f"CVEFixes-with-Context-Benchmark-depth-{max_call_depth}"

        return factory

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Estimate token usage for source samples."""

        return max(1, len(text) // 3) if text else 0

    def _write_datasets(
        self,
        samples_by_strategy: Mapping[str, list[BenchmarkSample]],
        metadata_name_factory: MetadataNameFactory | None = None,
        dataset_path_factory: DatasetPathFactory | None = None,
    ) -> dict[str, Path]:
        """Write benchmark datasets for all strategies."""

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
        """Delete a checked-out repository when configured."""

        if not self.delete_checkouts or repo_path is None or not repo_path.exists():
            return
        shutil.rmtree(str(repo_path))

    @staticmethod
    def _write_json(path: Path, payload: object) -> None:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, default=str) + "\n")
