"""Tests for loading audited CleanVul sample exclusions."""

import json
from pathlib import Path

import pytest

from services.benchmark.sample_exclusions import load_excluded_row_ids

_DATASET: Path = Path("/data/vulnerability_score_4.csv")


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "wrong_labels.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _document() -> dict[str, object]:
    return {
        "source_csv": "benchmarks/CleanVul/vulnerability_score_4.csv",
        "samples": [
            {"sample_id": "S-1", "cleanvul_source_row_ids": [789, 2754], "dataset_label": 1},
            {"sample_id": "S-2", "cleanvul_source_row_ids": [3607]},
        ],
        "disputed": [{"cleanvul_source_row_ids": [2976, 5318]}],
    }


def test_loads_samples_section_by_default(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())

    assert load_excluded_row_ids(path, _DATASET) == {789, 2754, 3607}


def test_unions_requested_sections(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())

    row_ids = load_excluded_row_ids(path, _DATASET, ("samples", "disputed"))

    assert row_ids == {789, 2754, 3607, 2976, 5318}


def test_accepts_file_without_source_csv(tmp_path: Path) -> None:
    document = _document()
    del document["source_csv"]
    path = _write(tmp_path, document)

    assert load_excluded_row_ids(path, Path("/other.csv")) == {789, 2754, 3607}


def test_rejects_ids_from_another_dataset_file(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())

    with pytest.raises(ValueError, match="vulnerability_score_3.csv"):
        load_excluded_row_ids(path, Path("/data/vulnerability_score_3.csv"))


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"samples": {"cleanvul_source_row_ids": [1]}},
        {"samples": [{"sample_id": "no ids"}]},
        {"samples": [{"cleanvul_source_row_ids": []}]},
        {"other": []},
    ],
)
def test_rejects_malformed_files(tmp_path: Path, document: object) -> None:
    path = _write(tmp_path, document)

    with pytest.raises(ValueError):
        load_excluded_row_ids(path, _DATASET)


def test_real_audit_file_loads_when_present() -> None:
    """The audit file this feature was built for parses against its own dataset."""

    audit = Path("/var/opt/llm4codesec-framework/benchmarks/cleanvul_wrong_labels.json")
    if not audit.exists():
        pytest.skip("audit file not available")

    row_ids = load_excluded_row_ids(audit, _DATASET)

    assert {789, 2754, 1693} <= row_ids
