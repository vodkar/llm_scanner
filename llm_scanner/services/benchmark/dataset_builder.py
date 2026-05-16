import json
from collections.abc import Callable, Mapping
from pathlib import Path

from pydantic import BaseModel

from models.benchmark.benchmark import BenchmarkDataset, BenchmarkMetadata, BenchmarkSample
from services.ranking.strategy_factory import RankingStrategies

DatasetPathFactory = Callable[[str], Path]
MetadataNameFactory = Callable[[str], str]


class DatasetBuilderService(BaseModel):
    output_dir: Path

    def _dataset_path(
        self,
        strategy_name: str,
        dataset_path_factory: DatasetPathFactory | None = None,
    ) -> Path:
        if dataset_path_factory is not None:
            return dataset_path_factory(strategy_name)
        if strategy_name == RankingStrategies.CURRENT.value:
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
    def _build_metadata(
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

    def write_datasets(
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
            self.write_json(dataset_path, dataset.model_dump(by_alias=True))
            dataset_paths[strategy_name] = dataset_path
        return dataset_paths

    @staticmethod
    def write_json(path: Path, payload: object) -> None:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=True, default=str) + "\n")
