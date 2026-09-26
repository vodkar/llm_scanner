import json
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

DEFAULT_EXCLUSION_SECTIONS: Final[tuple[str, ...]] = ("samples",)


class _ExcludedSample(BaseModel):
    """One audited sample; only its CleanVul row ids matter for exclusion."""

    model_config = ConfigDict(extra="ignore")

    cleanvul_source_row_ids: list[int] = Field(..., min_length=1)


def load_excluded_row_ids(
    exclusions_path: Path,
    dataset_path: Path,
    sections: Sequence[str] = DEFAULT_EXCLUSION_SECTIONS,
) -> frozenset[int]:
    """Read CleanVul row ids to exclude from a sample-exclusion JSON file.

    The file is a JSON object whose ``sections`` (e.g. ``samples``, ``disputed``)
    are lists of entries carrying ``cleanvul_source_row_ids`` — 0-based data-row
    indices into the CleanVul file. An optional top-level ``source_csv`` names
    that file; row ids are only meaningful against it.

    Args:
        exclusions_path: Path to the exclusion JSON file.
        dataset_path: CleanVul dataset the benchmark is built from.
        sections: Top-level list keys whose entries are excluded.

    Returns:
        Union of the row ids listed in ``sections``.

    Raises:
        ValueError: If the file is malformed, a section is missing, or
            ``source_csv`` names a different dataset file.
    """

    with open(exclusions_path, encoding="utf-8") as exclusions_file:
        document: object = json.load(exclusions_file)
    if not isinstance(document, dict):
        raise ValueError(f"{exclusions_path}: expected a JSON object at the top level")

    source_csv = document.get("source_csv")
    if isinstance(source_csv, str) and Path(source_csv).name != dataset_path.name:
        raise ValueError(
            f"{exclusions_path} lists row ids of {source_csv!r}, "
            f"but the dataset is {dataset_path.name!r}"
        )

    return frozenset(
        row_id
        for section in sections
        for sample in _section_samples(document, section, exclusions_path)
        for row_id in sample.cleanvul_source_row_ids
    )


def _section_samples(
    document: dict[str, object], section: str, exclusions_path: Path
) -> list[_ExcludedSample]:
    entries = document.get(section)
    if not isinstance(entries, list):
        raise ValueError(f"{exclusions_path}: section {section!r} is missing or not a list")
    try:
        return [_ExcludedSample.model_validate(entry) for entry in entries]
    except ValidationError as error:
        raise ValueError(f"{exclusions_path}: bad entry in section {section!r}: {error}") from error
