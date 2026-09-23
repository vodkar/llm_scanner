"""A Semgrep failure aborts a benchmark run instead of silently dropping the commit."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clients.analyzers.semgrep import SemgrepExecutionError
from services.benchmark.cleanvul_benchmark import CleanVulBenchmarkService
from services.benchmark.cleanvul_loader import CleanVulLoaderService
from services.benchmark.repo_checkout import RepoCheckoutService
from services.ranking.ranking import DummyNodeRankingStrategy


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CleanVulBenchmarkService:
    row = MagicMock(commit_url="https://github.com/o/r/commit/abc")
    monkeypatch.setattr(
        CleanVulLoaderService,
        "fetch_entries",
        lambda self: [([row], "https://github.com/o/r", "abc")],
    )
    monkeypatch.setattr(RepoCheckoutService, "checkout_repo", lambda self, **kwargs: tmp_path)
    monkeypatch.setattr(CleanVulBenchmarkService, "_repo_size_reason", lambda self, *a: None)
    monkeypatch.setattr(
        CleanVulBenchmarkService, "_build_entry_pair", lambda self, **kwargs: MagicMock()
    )
    monkeypatch.setattr(
        CleanVulBenchmarkService, "_entry_pair_budget_reason", lambda self, pair: None
    )
    monkeypatch.setattr(CleanVulBenchmarkService, "_delete_checkout", lambda self, path: None)
    return CleanVulBenchmarkService.model_validate(
        {
            "dataset_path": tmp_path / "cleanvul.csv",
            "output_dir": tmp_path / "out",
            "repo_cache_dir": tmp_path / "repos",
            "sample_count": 2,
            "max_call_depth": 2,
            "enable_semgrep": True,
            "strategy_factories": {"dummy": lambda _p: DummyNodeRankingStrategy()},
        }
    )


def _raise_semgrep(*args: object, **kwargs: object) -> None:
    del args, kwargs
    raise SemgrepExecutionError("registry unreachable")


def test_prepare_samples_propagates_semgrep_failure(
    service: CleanVulBenchmarkService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(CleanVulBenchmarkService, "_prepare_one_side", _raise_semgrep)

    with pytest.raises(SemgrepExecutionError, match="registry unreachable"):
        service.prepare_samples(tmp_path / "cache")


def test_build_propagates_semgrep_failure(
    service: CleanVulBenchmarkService, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(CleanVulBenchmarkService, "_scan_repository_for_entry", _raise_semgrep)

    with pytest.raises(SemgrepExecutionError, match="registry unreachable"):
        service.build()


def test_other_scan_failures_still_skip_the_commit(
    service: CleanVulBenchmarkService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise_value_error(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise ValueError("unparsable file")

    monkeypatch.setattr(CleanVulBenchmarkService, "_prepare_one_side", _raise_value_error)

    assert service.prepare_samples(tmp_path / "cache") == []
