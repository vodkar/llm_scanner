"""Tests for CVEFixes benchmark dataset generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from models.benchmark.cvefixes import CVEFixesEntry
from models.context import Context, FileSpans
from services.analyzer.cvefixes_benchmark import (
    CURRENT_STRATEGY_NAME,
    CVEFixesBenchmarkService,
)
from services.benchmark.cvefixes_loader import CVEFixesLoaderService
from services.benchmark.repo_checkout import RepoCheckoutService


def _build_entry(is_vulnerable: bool) -> CVEFixesEntry:
    """Create a benchmark entry fixture."""

    return CVEFixesEntry(
        cve_id="CVE-2024-0001",
        repo_url="https://example.com/org/repo.git",
        fix_hash="abcdef123456",
        files_spans=[FileSpans(Path("pkg/sample.py"), [(1, 2)])],
        description="Sample benchmark entry",
        cwe_id=79,
        severity="high",
        is_vulnerable=is_vulnerable,
    )


def test_build_all_ranking_strategies_writes_aligned_datasets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All ranking strategy datasets should contain the same accepted samples."""

    vulnerable_entry = _build_entry(is_vulnerable=True)
    fixed_entry = _build_entry(is_vulnerable=False)

    vulnerable_repo = tmp_path / "vulnerable"
    fixed_repo = tmp_path / "fixed"
    for repo_path in (vulnerable_repo, fixed_repo):
        source_file = repo_path / "pkg" / "sample.py"
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("def sample():\n    pass\n", encoding="utf-8")

    def _fetch_python_entries(self: CVEFixesLoaderService) -> list[CVEFixesEntry]:
        del self
        return [vulnerable_entry, fixed_entry]

    def _checkout_repo(
        self: RepoCheckoutService,
        repo_url: str,
        fix_hash: str,
        is_vulnerable: bool,
    ) -> Path:
        del self, repo_url, fix_hash
        return vulnerable_repo if is_vulnerable else fixed_repo

    monkeypatch.setattr(CVEFixesLoaderService, "fetch_python_entries", _fetch_python_entries)
    monkeypatch.setattr(RepoCheckoutService, "checkout_repo", _checkout_repo)

    def _scan_repository_for_entry(
        self: CVEFixesBenchmarkService,
        repo_path: Path,
        entry: CVEFixesEntry,
        strategy_factories: dict[str, object],
        max_call_depth: int,
    ) -> dict[str, Context]:
        del repo_path, max_call_depth
        return {
            strategy_name: Context(
                description=strategy_name,
                context_text=f"{strategy_name}:{'before' if entry.is_vulnerable else 'after'}",
                token_count=10,
            )
            for strategy_name in strategy_factories
        }

    monkeypatch.setattr(
        CVEFixesBenchmarkService,
        "_scan_repository_for_entry",
        _scan_repository_for_entry,
    )

    service = CVEFixesBenchmarkService(
        db_path=tmp_path / "dataset.sqlite",
        output_dir=tmp_path / "output",
        repo_cache_dir=tmp_path / "repos",
        sample_count=2,
        max_call_depth=2,
        token_budget=100,
        delete_checkouts=False,
    )

    dataset_paths, unassociated_path = service.build_all_ranking_strategies()

    assert set(dataset_paths) == {
        "current",
        "depth_repeats_context",
        "random_picking",
        "multiplicative_boost",
        "dummy",
    }

    strategy_payloads = {
        strategy_name: json.loads(dataset_path.read_text(encoding="utf-8"))
        for strategy_name, dataset_path in dataset_paths.items()
    }
    sample_id_sets = {
        tuple(sample["id"] for sample in payload["samples"])
        for payload in strategy_payloads.values()
    }
    label_sets = {
        tuple(sample["label"] for sample in payload["samples"])
        for payload in strategy_payloads.values()
    }

    assert sample_id_sets == {("ContextAssembler-1", "ContextAssembler-2")}
    assert label_sets == {(1, 0)}
    assert json.loads(unassociated_path.read_text(encoding="utf-8")) == []


def test_build_all_ranking_strategies_skips_pairs_over_token_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before/after source samples above the token budget should be skipped."""

    vulnerable_entry = _build_entry(is_vulnerable=True)
    fixed_entry = _build_entry(is_vulnerable=False)

    vulnerable_repo = tmp_path / "vulnerable"
    fixed_repo = tmp_path / "fixed"
    for repo_path in (vulnerable_repo, fixed_repo):
        source_file = repo_path / "pkg" / "sample.py"
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("x = '" + ("a" * 400) + "'\n", encoding="utf-8")

    def _fetch_python_entries(self: CVEFixesLoaderService) -> list[CVEFixesEntry]:
        del self
        return [vulnerable_entry, fixed_entry]

    def _checkout_repo(
        self: RepoCheckoutService,
        repo_url: str,
        fix_hash: str,
        is_vulnerable: bool,
    ) -> Path:
        del self, repo_url, fix_hash
        return vulnerable_repo if is_vulnerable else fixed_repo

    monkeypatch.setattr(CVEFixesLoaderService, "fetch_python_entries", _fetch_python_entries)
    monkeypatch.setattr(RepoCheckoutService, "checkout_repo", _checkout_repo)

    scan_calls = {"count": 0}

    def _scan_repository_for_entry(
        self: CVEFixesBenchmarkService,
        repo_path: Path,
        entry: CVEFixesEntry,
        strategy_factories: dict[str, object],
        max_call_depth: int,
    ) -> dict[str, Context]:
        del self, repo_path, entry, strategy_factories, max_call_depth
        scan_calls["count"] += 1
        return {}

    monkeypatch.setattr(
        CVEFixesBenchmarkService,
        "_scan_repository_for_entry",
        _scan_repository_for_entry,
    )

    service = CVEFixesBenchmarkService(
        db_path=tmp_path / "dataset.sqlite",
        output_dir=tmp_path / "output",
        repo_cache_dir=tmp_path / "repos",
        sample_count=2,
        max_call_depth=2,
        token_budget=10,
        delete_checkouts=False,
    )

    dataset_paths, unassociated_path = service.build_all_ranking_strategies()

    assert scan_calls["count"] == 0
    for dataset_path in dataset_paths.values():
        payload = json.loads(dataset_path.read_text(encoding="utf-8"))
        assert payload["samples"] == []
        assert payload["metadata"]["total_samples"] == 0

    unassociated_payload = json.loads(unassociated_path.read_text(encoding="utf-8"))
    assert [item["reason"] for item in unassociated_payload] == [
        "source_sample_exceeds_token_budget",
        "source_sample_exceeds_token_budget",
    ]


def test_build_all_ranking_strategies_uses_separate_checkout_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vulnerable and fixed entries should not share the same checkout path."""

    vulnerable_entry = _build_entry(is_vulnerable=True)
    fixed_entry = _build_entry(is_vulnerable=False)

    vulnerable_repo = tmp_path / "repos" / "vulnerable" / "repo"
    fixed_repo = tmp_path / "repos" / "fixed" / "repo"
    vulnerable_source = vulnerable_repo / "pkg" / "sample.py"
    fixed_source = fixed_repo / "pkg" / "sample.py"
    vulnerable_source.parent.mkdir(parents=True, exist_ok=True)
    fixed_source.parent.mkdir(parents=True, exist_ok=True)
    vulnerable_source.write_text("def before():\n    pass\n", encoding="utf-8")
    fixed_source.write_text("def after():\n    pass\n", encoding="utf-8")

    def _fetch_python_entries(self: CVEFixesLoaderService) -> list[CVEFixesEntry]:
        del self
        return [vulnerable_entry, fixed_entry]

    def _checkout_repo(
        self: RepoCheckoutService,
        repo_url: str,
        fix_hash: str,
        is_vulnerable: bool,
    ) -> Path:
        del repo_url, fix_hash, is_vulnerable
        return self.cache_dir / "repo"

    seen_sources: dict[bool, str] = {}

    def _scan_repository_for_entry(
        self: CVEFixesBenchmarkService,
        repo_path: Path,
        entry: CVEFixesEntry,
        strategy_factories: dict[str, object],
        max_call_depth: int,
    ) -> dict[str, Context]:
        del self, max_call_depth
        seen_sources[entry.is_vulnerable] = (repo_path / entry.files_spans[0].file_path).read_text(
            encoding="utf-8"
        )
        return {
            strategy_name: Context(
                description=strategy_name,
                context_text=f"{strategy_name}:{'before' if entry.is_vulnerable else 'after'}",
                token_count=10,
            )
            for strategy_name in strategy_factories
        }

    monkeypatch.setattr(CVEFixesLoaderService, "fetch_python_entries", _fetch_python_entries)
    monkeypatch.setattr(RepoCheckoutService, "checkout_repo", _checkout_repo)
    monkeypatch.setattr(
        CVEFixesBenchmarkService,
        "_scan_repository_for_entry",
        _scan_repository_for_entry,
    )

    service = CVEFixesBenchmarkService(
        db_path=tmp_path / "dataset.sqlite",
        output_dir=tmp_path / "output",
        repo_cache_dir=tmp_path / "repos",
        sample_count=2,
        max_call_depth=2,
        token_budget=100,
        delete_checkouts=False,
    )

    dataset_paths, _ = service.build_all_ranking_strategies()

    assert set(dataset_paths) == {
        "current",
        "depth_repeats_context",
        "random_picking",
        "multiplicative_boost",
        "dummy",
    }
    assert seen_sources[True] == "def before():\n    pass\n"
    assert seen_sources[False] == "def after():\n    pass\n"


def test_build_all_depth_sizes_writes_depth_specific_datasets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Depth sweep should write one dataset per configured max call depth."""

    vulnerable_entry = _build_entry(is_vulnerable=True)
    fixed_entry = _build_entry(is_vulnerable=False)

    vulnerable_repo = tmp_path / "vulnerable"
    fixed_repo = tmp_path / "fixed"
    for repo_path in (vulnerable_repo, fixed_repo):
        source_file = repo_path / "pkg" / "sample.py"
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("def sample():\n    pass\n", encoding="utf-8")

    def _fetch_python_entries(self: CVEFixesLoaderService) -> list[CVEFixesEntry]:
        del self
        return [vulnerable_entry, fixed_entry]

    def _checkout_repo(
        self: RepoCheckoutService,
        repo_url: str,
        fix_hash: str,
        is_vulnerable: bool,
    ) -> Path:
        del self, repo_url, fix_hash
        return vulnerable_repo if is_vulnerable else fixed_repo

    observed_depths: list[int] = []

    def _scan_repository_for_entry(
        self: CVEFixesBenchmarkService,
        repo_path: Path,
        entry: CVEFixesEntry,
        strategy_factories: dict[str, object],
        max_call_depth: int,
    ) -> dict[str, Context]:
        del self, repo_path, strategy_factories
        observed_depths.append(max_call_depth)
        return {
            CURRENT_STRATEGY_NAME: Context(
                description=f"depth-{max_call_depth}",
                context_text=f"depth-{max_call_depth}:{int(entry.is_vulnerable)}",
                token_count=10,
            )
        }

    monkeypatch.setattr(CVEFixesLoaderService, "fetch_python_entries", _fetch_python_entries)
    monkeypatch.setattr(RepoCheckoutService, "checkout_repo", _checkout_repo)
    monkeypatch.setattr(
        CVEFixesBenchmarkService,
        "_scan_repository_for_entry",
        _scan_repository_for_entry,
    )

    service = CVEFixesBenchmarkService(
        db_path=tmp_path / "dataset.sqlite",
        output_dir=tmp_path / "output",
        repo_cache_dir=tmp_path / "repos",
        sample_count=2,
        max_call_depth=3,
        token_budget=100,
        delete_checkouts=False,
    )

    dataset_paths, unassociated_paths = service.build_all_depth_sizes()

    assert set(dataset_paths) == {2, 3, 4, 5, 6}
    assert set(unassociated_paths) == {2, 3, 4, 5, 6}
    assert sorted(set(observed_depths)) == [2, 3, 4, 5, 6]

    for depth, dataset_path in dataset_paths.items():
        payload = json.loads(dataset_path.read_text(encoding="utf-8"))
        assert payload["metadata"]["name"] == f"CVEFixes-with-Context-Benchmark-depth-{depth}"
        assert [sample["id"] for sample in payload["samples"]] == [
            f"ContextAssemblerDepth{depth}-1",
            f"ContextAssemblerDepth{depth}-2",
        ]
        assert [sample["label"] for sample in payload["samples"]] == [1, 0]

    for depth, unassociated_path in unassociated_paths.items():
        assert unassociated_path.name == f"cvefixes_unassociated_depth_{depth}.json"
        assert json.loads(unassociated_path.read_text(encoding="utf-8")) == []
