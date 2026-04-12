#!/usr/bin/env python3
"""Concatenate matching benchmark datasets from compare_rankings directories."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Final, TypedDict, cast

DEFAULT_DATA_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "data"
DEFAULT_INPUT_GLOB: Final[str] = "compare_rankings*"
DEFAULT_OUTPUT_DIRNAME: Final[str] = "compare_rankings_combined"


class DatasetMetadata(TypedDict):
    """Metadata stored in benchmark JSON files."""

    name: str
    task_type: str
    total_samples: int
    cwe_distribution: dict[str, int]


class Dataset(TypedDict):
    """Benchmark dataset representation."""

    metadata: DatasetMetadata
    samples: list[dict[str, object]]


type ArrayDataset = list[object]


def stable_json_key(value: object) -> str:
    """Build a stable string key for JSON-compatible values."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sample_dedupe_key(sample: dict[str, object]) -> str:
    """Build a deduplication key for benchmark samples."""

    metadata = sample.get("metadata")
    cve_id: object | None = None
    if isinstance(metadata, dict):
        typed_metadata = cast(dict[str, object], metadata)
        cve_id = typed_metadata.get("CVEFixes-Number")

    label = sample.get("label")
    if isinstance(cve_id, str) and label is not None:
        return f"{cve_id}::{label}"

    return stable_json_key(sample)


def dedupe_object_entries(entries: list[dict[str, object]]) -> tuple[list[dict[str, object]], int]:
    """Deduplicate benchmark entries while preserving input order."""

    seen_keys: set[str] = set()
    unique_entries: list[dict[str, object]] = []

    for entry in entries:
        dedupe_key = sample_dedupe_key(entry)
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        unique_entries.append(entry)

    return unique_entries, len(entries) - len(unique_entries)


def dedupe_array_entries(entries: ArrayDataset) -> tuple[ArrayDataset, int]:
    """Deduplicate list-style dataset entries while preserving input order."""

    seen_keys: set[str] = set()
    unique_entries: ArrayDataset = []

    for entry in entries:
        dedupe_key = stable_json_key(entry)
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        unique_entries.append(entry)

    return unique_entries, len(entries) - len(unique_entries)


def sample_cwe_key(sample: dict[str, object]) -> str | None:
    """Extract a normalized CWE key from a benchmark sample."""

    metadata = sample.get("metadata")
    if not isinstance(metadata, dict):
        return None

    typed_metadata = cast(dict[str, object], metadata)
    cwe_number = typed_metadata.get("cwe_number")
    if cwe_number is None:
        return None
    if isinstance(cwe_number, int):
        return f"CWE-{cwe_number}"
    if isinstance(cwe_number, str):
        return cwe_number if cwe_number.startswith("CWE-") else f"CWE-{cwe_number}"
    return None


def build_cwe_distribution(samples: list[dict[str, object]]) -> dict[str, int]:
    """Build benchmark CWE distribution from the merged unique samples."""

    cwe_distribution: Counter[str] = Counter()
    for sample in samples:
        cwe_key = sample_cwe_key(sample)
        if cwe_key is not None:
            cwe_distribution[cwe_key] += 1
    return dict(sorted(cwe_distribution.items()))


def require_object(value: object, context: str) -> dict[str, object]:
    """Validate that a JSON value is an object."""

    if not isinstance(value, dict):
        raise ValueError(f"{context} must be a JSON object.")
    return cast(dict[str, object], value)


def require_array(value: object, context: str) -> list[object]:
    """Validate that a JSON value is an array."""

    if not isinstance(value, list):
        raise ValueError(f"{context} must be a JSON array.")
    return cast(list[object], value)


def get_required_field(data: dict[str, object], key: str, context: str) -> object:
    """Return a required object field from parsed JSON data."""

    if key not in data:
        raise ValueError(f"{context} is missing required field {key!r}.")
    return data[key]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Concatenate matching JSON benchmark datasets from compare_rankings* "
            "directories into a single output directory."
        )
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Base data directory containing compare_rankings folders.",
    )
    parser.add_argument(
        "--input-glob",
        default=DEFAULT_INPUT_GLOB,
        help="Glob used to find dataset directories under --data-dir.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Directory where merged JSON files will be written. Defaults to "
            "<data-dir>/compare_rankings_combined."
        ),
    )
    return parser.parse_args()


def discover_dataset_groups(
    data_dir: Path,
    input_glob: str,
    excluded_dir: Path | None = None,
) -> dict[str, list[Path]]:
    """Group matching JSON files by filename across compare_rankings directories."""

    grouped_files: dict[str, list[Path]] = defaultdict(list)
    excluded_dir_resolved = excluded_dir.resolve() if excluded_dir is not None else None
    dataset_dirs = sorted(
        path
        for path in data_dir.glob(input_glob)
        if path.is_dir()
        and (excluded_dir_resolved is None or path.resolve() != excluded_dir_resolved)
    )

    if not dataset_dirs:
        raise FileNotFoundError(
            f"No dataset directories matching {input_glob!r} found in {data_dir}."
        )

    for dataset_dir in dataset_dirs:
        json_files = sorted(path for path in dataset_dir.glob("*.json") if path.is_file())
        if not json_files:
            continue

        for json_file in json_files:
            grouped_files[json_file.name].append(json_file)

    if not grouped_files:
        raise FileNotFoundError(
            f"No JSON files found in directories matching {input_glob!r} under {data_dir}."
        )

    return dict(sorted(grouped_files.items()))


def load_dataset(dataset_path: Path) -> Dataset:
    """Load and validate a dataset file."""

    raw_data = require_object(
        json.loads(dataset_path.read_text()),
        context=f"Dataset {dataset_path}",
    )

    metadata = require_object(
        get_required_field(raw_data, "metadata", context=f"Dataset {dataset_path}"),
        context=f"Dataset {dataset_path} metadata",
    )
    samples = require_array(
        get_required_field(raw_data, "samples", context=f"Dataset {dataset_path}"),
        context=f"Dataset {dataset_path} samples",
    )

    name = get_required_field(metadata, "name", context=f"Dataset {dataset_path} metadata")
    task_type = get_required_field(
        metadata,
        "task_type",
        context=f"Dataset {dataset_path} metadata",
    )
    cwe_distribution_raw = require_object(
        get_required_field(
            metadata,
            "cwe_distribution",
            context=f"Dataset {dataset_path} metadata",
        ),
        context=f"Dataset {dataset_path} metadata.cwe_distribution",
    )

    if not isinstance(name, str):
        raise ValueError(f"Dataset {dataset_path} metadata.name must be a string.")
    if not isinstance(task_type, str):
        raise ValueError(f"Dataset {dataset_path} metadata.task_type must be a string.")

    cwe_distribution: dict[str, int] = {}
    for cwe, count in cwe_distribution_raw.items():
        if not isinstance(count, int):
            raise ValueError(
                f"Dataset {dataset_path} has invalid cwe_distribution entry {cwe!r}: {count!r}."
            )
        cwe_distribution[cwe] = count

    validated_samples: list[dict[str, object]] = []
    for sample in samples:
        if not isinstance(sample, dict):
            raise ValueError(f"Dataset {dataset_path} contains a non-object sample: {sample!r}.")
        validated_samples.append(cast(dict[str, object], sample))

    return Dataset(
        metadata=DatasetMetadata(
            name=name,
            task_type=task_type,
            total_samples=len(validated_samples),
            cwe_distribution=cwe_distribution,
        ),
        samples=validated_samples,
    )


def load_array_dataset(dataset_path: Path) -> ArrayDataset:
    """Load and validate a top-level array dataset file."""

    return require_array(
        json.loads(dataset_path.read_text()),
        context=f"Dataset {dataset_path}",
    )


def merge_datasets(dataset_paths: list[Path]) -> Dataset:
    """Merge datasets that share the same filename across directories."""

    datasets = [load_dataset(path) for path in dataset_paths]
    names = {dataset["metadata"]["name"] for dataset in datasets}
    task_types = {dataset["metadata"]["task_type"] for dataset in datasets}

    if len(names) != 1:
        raise ValueError(
            "Cannot merge datasets with different metadata.name values: "
            f"{sorted(names)} from {[str(path) for path in dataset_paths]}"
        )
    if len(task_types) != 1:
        raise ValueError(
            "Cannot merge datasets with different metadata.task_type values: "
            f"{sorted(task_types)} from {[str(path) for path in dataset_paths]}"
        )

    combined_samples: list[dict[str, object]] = []

    for dataset in datasets:
        combined_samples.extend(dataset["samples"])

    unique_samples, _ = dedupe_object_entries(combined_samples)
    cwe_distribution = build_cwe_distribution(unique_samples)

    return Dataset(
        metadata=DatasetMetadata(
            name=next(iter(names)),
            task_type=next(iter(task_types)),
            total_samples=len(unique_samples),
            cwe_distribution=cwe_distribution,
        ),
        samples=unique_samples,
    )


def merge_array_datasets(dataset_paths: list[Path]) -> ArrayDataset:
    """Merge list-based datasets that share the same filename across directories."""

    combined_entries: ArrayDataset = []
    for dataset_path in dataset_paths:
        combined_entries.extend(load_array_dataset(dataset_path))
    unique_entries, _ = dedupe_array_entries(combined_entries)
    return unique_entries


def merge_dataset_group(dataset_paths: list[Path]) -> tuple[object, int, int]:
    """Merge a dataset group based on the top-level JSON shape."""

    if not dataset_paths:
        raise ValueError("Expected at least one dataset path to merge.")

    first_payload = json.loads(dataset_paths[0].read_text())
    if isinstance(first_payload, dict):
        merged_object_entries: list[dict[str, object]] = []
        for dataset_path in dataset_paths:
            merged_object_entries.extend(load_dataset(dataset_path)["samples"])
        _, duplicate_count = dedupe_object_entries(merged_object_entries)
        merged_dataset = merge_datasets(dataset_paths)
        return merged_dataset, merged_dataset["metadata"]["total_samples"], duplicate_count
    if isinstance(first_payload, list):
        merged_array_entries: ArrayDataset = []
        for dataset_path in dataset_paths:
            merged_array_entries.extend(load_array_dataset(dataset_path))
        _, duplicate_count = dedupe_array_entries(merged_array_entries)
        merged_dataset = merge_array_datasets(dataset_paths)  # type: ignore
        return merged_dataset, len(merged_dataset), duplicate_count

    raise ValueError(
        f"Dataset {dataset_paths[0]} must contain either a top-level JSON object or array."
    )


def write_merged_datasets(grouped_files: dict[str, list[Path]], output_dir: Path) -> None:
    """Write merged datasets to the output directory."""

    output_dir.mkdir(parents=True, exist_ok=True)

    for filename, dataset_paths in grouped_files.items():
        merged_dataset, entry_count, duplicate_count = merge_dataset_group(dataset_paths)
        output_path = output_dir / filename
        output_path.write_text(json.dumps(merged_dataset, indent=2))
        print(
            f"Written {entry_count} entries to {output_path} from {len(dataset_paths)} files "
            f"({duplicate_count} duplicates removed)"
        )


def main() -> None:
    """Merge datasets from compare_rankings directories."""

    args = parse_args()
    data_dir = args.data_dir.resolve()
    output_dir = (
        args.output_dir.resolve()
        if args.output_dir is not None
        else data_dir / DEFAULT_OUTPUT_DIRNAME
    )

    grouped_files = discover_dataset_groups(
        data_dir=data_dir,
        input_glob=args.input_glob,
        excluded_dir=output_dir,
    )
    write_merged_datasets(grouped_files=grouped_files, output_dir=output_dir)


if __name__ == "__main__":
    main()
