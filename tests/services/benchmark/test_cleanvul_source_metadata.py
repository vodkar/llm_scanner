"""Samples record which dataset, file and rows they were built from."""

import json
from pathlib import Path

import pytest

from models.benchmark.benchmark import CleanVulSampleMetadata
from models.context import Context
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService
from services.benchmark.cleanvul_loader import CleanVulRow
from services.ranking.ranking import DummyNodeRankingStrategy

_VULNERABLE = "def run(cmd):\n    os.system(cmd)\n"
_FIXED = "def run(cmd):\n    subprocess.run([cmd])\n"


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _service(tmp_path: Path) -> CleanVulBenchmarkService:
    return CleanVulBenchmarkService.model_validate(
        {
            "dataset_path": tmp_path / "vulnerability_score_4.csv",
            "output_dir": tmp_path / "out",
            "repo_cache_dir": tmp_path / "repos",
            "sample_count": 2,
            "max_call_depth": 2,
            "strategy_factories": {"dummy": lambda _p: DummyNodeRankingStrategy()},
        }
    )


def _row(row_id: int, func_before: str, func_after: str) -> CleanVulRow:
    return CleanVulRow(
        row_id=row_id,
        func_before=func_before,
        func_after=func_after,
        commit_url="https://github.com/o/r/commit/abc",
        file_name="app.py",
        cwe_id="CWE-78",
        vulnerability_score=4,
        extension="py",
    )


def _checkouts(tmp_path: Path) -> tuple[Path, Path]:
    vulnerable = tmp_path / "vulnerable"
    fixed = tmp_path / "fixed"
    vulnerable.mkdir()
    fixed.mkdir()
    (vulnerable / "app.py").write_text(_VULNERABLE, encoding="utf-8")
    (fixed / "app.py").write_text(_FIXED, encoding="utf-8")
    return vulnerable, fixed


def test_entry_pair_records_source_rows_that_were_located(tmp_path: Path) -> None:
    vulnerable, fixed = _checkouts(tmp_path)
    rows = [
        _row(17, _VULNERABLE, _FIXED),
        _row(42, "def missing():\n    pass\n", "def missing():\n    return 1\n"),
    ]

    pair = _service(tmp_path)._build_entry_pair(
        rows=rows,
        repo_url="https://github.com/o/r",
        fix_hash="abc",
        vulnerable_repo_path=vulnerable,
        fixed_repo_path=fixed,
    )

    assert pair is not None
    for entry in (pair.vulnerable_entry, pair.fixed_entry):
        assert entry.source_dataset == "CleanVul"
        assert entry.source_file == "vulnerability_score_4.csv"
        assert entry.source_row_ids == [17]


def test_sample_metadata_carries_source_identity(tmp_path: Path) -> None:
    vulnerable, fixed = _checkouts(tmp_path)
    service = _service(tmp_path)
    pair = service._build_entry_pair(
        rows=[_row(17, _VULNERABLE, _FIXED)],
        repo_url="https://github.com/o/r",
        fix_hash="abc",
        vulnerable_repo_path=vulnerable,
        fixed_repo_path=fixed,
    )
    assert pair is not None
    context = Context(description="d", context_text="x", token_count=1)

    sample = service._to_sample(pair.vulnerable_entry, context, "s-1")

    assert isinstance(sample.metadata, CleanVulSampleMetadata)
    dumped = json.loads(sample.model_dump_json(by_alias=True))["metadata"]
    assert dumped["source_dataset"] == "CleanVul"
    assert dumped["source_file"] == "vulnerability_score_4.csv"
    assert dumped["source_row_ids"] == [17]


def test_cache_loader_options_include_dataset_file(tmp_path: Path) -> None:
    """Row ids depend on the file, so cached entries must not cross files."""

    assert _service(tmp_path)._cache_loader_options() == {
        "min_score": 4,
        "dataset_file": "vulnerability_score_4.csv",
    }
