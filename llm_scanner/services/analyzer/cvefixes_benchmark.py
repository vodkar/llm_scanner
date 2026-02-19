from __future__ import annotations

import json
import logging
import random
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from clients.neo4j import Neo4jConfig, build_client
from context_assembler import ContextAssemblerService
from models.benchmark.benchmark import (
    BenchmarkDataset,
    BenchmarkMetadata,
    BenchmarkSample,
    BenchmarkSampleMetadata,
    UnassociatedSample,
)
from models.benchmark.cvefixes import CVEFixesEntry
from models.context import ContextAssembly, FindingContext
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.context import ContextRepository
from repositories.graph import GraphRepository
from services.analyzer.bandit import BanditAnalyzerService
from services.analyzer.dlint import DlintAnalyzerService
from services.benchmark.cvefixes_loader import CVEFixesLoaderService
from services.benchmark.repo_checkout import RepoCheckoutService
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder

logger = logging.getLogger(__name__)


class CVEFixesBenchmarkService(BaseModel):
    """Build the CVEFixes-with-context benchmark dataset."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    db_path: Path
    output_dir: Path
    repo_cache_dir: Path
    sample_count: int
    seed: int | None = None
    neo4j_config: Neo4jConfig = Field(default_factory=Neo4jConfig)
    max_call_depth: int = 3
    token_budget: int = 2048

    def build(self) -> tuple[Path, Path]:
        """Generate the benchmark JSON files.

        Returns:
            Tuple of paths to the main dataset and unassociated dataset files.
        """

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.repo_cache_dir.mkdir(parents=True, exist_ok=True)

        loader = CVEFixesLoaderService(db_path=self.db_path)
        candidates = loader.fetch_python_entries()
        rng = random.Random(self.seed)
        rng.shuffle(candidates)

        samples: list[BenchmarkSample] = []
        unassociated: list[UnassociatedSample] = []

        repo_service = RepoCheckoutService(cache_dir=self.repo_cache_dir)

        for entry in candidates:
            if len(samples) >= self.sample_count:
                break

            try:
                repo_path = repo_service.checkout_vulnerable_repo(entry.repo_url, entry.fix_hash)
            except Exception:
                logger.exception("Failed to checkout %s at %s", entry.repo_url, entry.fix_hash)
                unassociated.append(
                    UnassociatedSample(
                        entry=self._entry_metadata(entry),
                        reason="checkout_failed",
                        contexts=[],
                    )
                )
                continue

            context = self._scan_repository(repo_path)
            logger.info(
                "Scanned repository for entry %s: found %d contexts",
                entry.cve_id,
                len(context.findings),
            )

            associated, non_associated = self._split_associations(entry, context)

            logger.info(
                "Entry %s: found %d associated and %d non-associated contexts",
                entry.cve_id,
                len(associated),
                len(non_associated),
            )

            if associated:
                chosen = self._choose_associated(entry, associated)
                samples.append(
                    self._to_sample(
                        entry=entry,
                        context=chosen,
                        label=1,
                        sample_id=f"ContextAssembler-{len(samples) + 1}",
                    )
                )
                continue

            if non_associated:
                samples.append(
                    self._to_sample(
                        entry=entry,
                        context=non_associated[0],
                        label=0,
                        sample_id=f"ContextAssembler-{len(samples) + 1}",
                    )
                )
                unassociated.append(
                    UnassociatedSample(
                        entry=self._entry_metadata(entry),
                        reason="no_file_line_match",
                        contexts=non_associated,
                    )
                )
                continue

            unassociated.append(
                UnassociatedSample(
                    entry=self._entry_metadata(entry),
                    reason="no_findings",
                    contexts=[],
                )
            )

        if len(samples) < self.sample_count:
            raise ValueError(
                f"Only collected {len(samples)} samples (requested {self.sample_count})"
            )

        dataset = BenchmarkDataset(
            metadata=self._build_metadata(samples),
            samples=samples,
        )
        main_path = self.output_dir / "cvefixes_context_benchmark.json"
        unassociated_path = self.output_dir / "cvefixes_unassociated.json"

        self._write_json(main_path, dataset.model_dump(by_alias=True))
        self._write_json(
            unassociated_path, [item.model_dump(by_alias=True) for item in unassociated[:2]]
        )

        return main_path, unassociated_path

    def _scan_repository(self, repo_path: Path) -> ContextAssembly:
        with build_client(
            self.neo4j_config.uri,
            self.neo4j_config.user,
            self.neo4j_config.password,
        ) as neo4j_client:
            graph_repository = GraphRepository(neo4j_client)
            nodes, edges = CPGDirectoryBuilder(root=repo_path).build()
            graph_repository.load(nodes, edges)

            dlint_service = DlintAnalyzerService(
                target=repo_path,
                graph_repository=graph_repository,
                findings_repository=DlintFindingsRepository(client=neo4j_client),
            )
            dlint_service.enrich_graph_with_findings()

            bandit_service = BanditAnalyzerService(
                target=repo_path,
                graph_repository=graph_repository,
                findings_repository=BanditFindingsRepository(client=neo4j_client),
            )
            bandit_service.enrich_graph_with_findings()

            context_repository = ContextRepository(client=neo4j_client)
            context_service = ContextAssemblerService(
                project_root=repo_path,
                bandit_repository=BanditFindingsRepository(client=neo4j_client),
                dlint_repository=DlintFindingsRepository(client=neo4j_client),
                context_repository=context_repository,
                max_call_depth=self.max_call_depth,
                token_budget=self.token_budget,
            )
            return context_service.assemble()

    def _split_associations(
        self, entry: CVEFixesEntry, context: ContextAssembly
    ) -> tuple[list[FindingContext], list[FindingContext]]:
        associated: list[FindingContext] = []
        non_associated: list[FindingContext] = []
        target_file = Path(entry.file_path.as_posix())
        for finding in context.findings:
            if (
                finding.file == target_file
                and entry.start_line <= finding.line_number <= entry.end_line
            ):
                associated.append(finding)
            else:
                non_associated.append(finding)
        return associated, non_associated

    def _choose_associated(
        self, entry: CVEFixesEntry, candidates: list[FindingContext]
    ) -> FindingContext:
        return min(
            candidates,
            key=lambda finding: abs(finding.line_number - entry.start_line),
        )

    def _to_sample(
        self,
        *,
        entry: CVEFixesEntry,
        context: FindingContext,
        label: int,
        sample_id: str,
    ) -> BenchmarkSample:
        return BenchmarkSample(
            id=sample_id,
            code=context.context_text,
            label=label,
            metadata=self._entry_metadata(entry),
            cwe_types=[],
            severity=entry.severity or "unknown",
        )

    def _entry_metadata(self, entry: CVEFixesEntry) -> BenchmarkSampleMetadata:
        payload: dict[str, object] = {
            "original_filename": entry.file_path.as_posix(),
            "CWEFixes-Number": entry.cve_id,
            "description": entry.description,
            "cwe_number": entry.cwe_id,
        }
        return BenchmarkSampleMetadata.model_validate(payload)

    def _build_metadata(self, samples: list[BenchmarkSample]) -> BenchmarkMetadata:
        distribution: dict[str, int] = {}
        for sample in samples:
            cwe_number = sample.metadata.cwe_number
            if cwe_number is None:
                continue
            key = f"CWE-{cwe_number}"
            distribution[key] = distribution.get(key, 0) + 1

        return BenchmarkMetadata(
            name="CVEFixes-with-Context-Benchmark",
            task_type="binary",
            total_samples=len(samples),
            cwe_distribution=distribution,
        )

    @staticmethod
    def _write_json(path: Path, payload: object) -> None:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, default=str) + "\n")
