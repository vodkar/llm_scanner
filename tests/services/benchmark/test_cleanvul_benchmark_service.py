"""Tests for CleanVul benchmark dataset generation."""

import json
from pathlib import Path

import pytest

from models.benchmark.cleanvul import CleanVulEntry
from models.context import Context, FileSpans
from services.benchmark.cleanvul_benchmark import (
    CleanVulBenchmarkService,
    _CleanVulEntryPair,
)
from services.benchmark.cleanvul_loader import CleanVulLoaderService, CleanVulRow
from services.benchmark.repo_checkout import RepoCheckoutService

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_COMMIT_URL = "https://github.com/owner/repo/commit/abcdef123456"


def _make_row(**overrides: object) -> CleanVulRow:
    base = CleanVulRow(
        func_before="def foo():\n    bad()",
        func_after="def foo():\n    good()",
        commit_url=_COMMIT_URL,
        file_name="pkg/sample.py",
        cve_id="CVE-2024-0001",
        cwe_id="CWE-79",
        vulnerability_score=3,
        extension="py",
        is_test=False,
        commit_msg="fix: patch XSS",
    )
    return base.model_copy(update=overrides)


def _make_entry(is_vulnerable: bool, func_code: str = "def foo():\n    pass") -> CleanVulEntry:
    return CleanVulEntry(
        commit_url=_COMMIT_URL,
        repo_url="https://github.com/owner/repo",
        fix_hash="abcdef123456",
        file_name="pkg/sample.py",
        func_code=func_code,
        files_spans=[FileSpans(Path("pkg/sample.py"), [(1, 2)])],
        cve_id="CVE-2024-0001",
        cwe_id=79,
        cwe_ids=[79],
        vulnerability_score=3,
        commit_msg="fix: patch XSS",
        is_vulnerable=is_vulnerable,
    )


def _make_pair(
    func_code_vulnerable: str = "def foo():\n    bad()",
    func_code_fixed: str = "def foo():\n    good()",
) -> _CleanVulEntryPair:
    return _CleanVulEntryPair(
        vulnerable_entry=_make_entry(is_vulnerable=True, func_code=func_code_vulnerable),
        fixed_entry=_make_entry(is_vulnerable=False, func_code=func_code_fixed),
    )


def _make_service(tmp_path: Path, **overrides: object) -> CleanVulBenchmarkService:
    defaults: dict[str, object] = dict(
        dataset_path=tmp_path / "cleanvul.csv",
        output_dir=tmp_path / "output",
        repo_cache_dir=tmp_path / "repos",
        sample_count=2,
        max_call_depth=2,
        token_budget=100,
        delete_checkouts=False,
        # The tests monkeypatch `_scan_repository_for_entry`, so the factory
        # callable is never actually invoked; we just need any one-entry
        # mapping so the new `strategy_factories` requirement is satisfied.
        strategy_factories={"current": lambda _repo_path: None},
    )
    defaults.update(overrides)
    return CleanVulBenchmarkService.model_validate(defaults)


# ---------------------------------------------------------------------------
# build — happy path
# ---------------------------------------------------------------------------


def test_build_writes_dataset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: dataset with label pair (1,0)."""
    row = _make_row()
    pair = _make_pair()

    vulnerable_repo = tmp_path / "repos" / "vulnerable"
    fixed_repo = tmp_path / "repos" / "fixed"
    vulnerable_repo.mkdir(parents=True)
    fixed_repo.mkdir(parents=True)

    def _fetch_entries(
        self: CleanVulLoaderService,
    ) -> list[tuple[list[CleanVulRow], str, str]]:
        del self
        return [([row], "https://github.com/owner/repo", "abcdef123456")]

    def _checkout_repo(
        self: RepoCheckoutService, repo_url: str, fix_hash: str, is_vulnerable: bool
    ) -> Path:
        del self, repo_url, fix_hash
        return vulnerable_repo if is_vulnerable else fixed_repo

    def _build_entry_pair(
        self: CleanVulBenchmarkService,
        rows: list[CleanVulRow],
        repo_url: str,
        fix_hash: str,
        vulnerable_repo_path: Path,
        fixed_repo_path: Path,
    ) -> _CleanVulEntryPair:
        del self, rows, repo_url, fix_hash, vulnerable_repo_path, fixed_repo_path
        return pair

    def _scan_repository_for_entry(
        self: CleanVulBenchmarkService,
        repo_path: Path,
        entry: CleanVulEntry,
        strategy_factories: dict[str, object],
    ) -> dict[str, Context]:
        del self, repo_path
        return {
            strategy_name: Context(
                description=strategy_name,
                context_text=f"{'vuln' if entry.is_vulnerable else 'fixed'}-context",
                token_count=10,
            )
            for strategy_name in strategy_factories
        }

    monkeypatch.setattr(CleanVulLoaderService, "fetch_entries", _fetch_entries)
    monkeypatch.setattr(RepoCheckoutService, "checkout_repo", _checkout_repo)
    monkeypatch.setattr(CleanVulBenchmarkService, "_build_entry_pair", _build_entry_pair)
    monkeypatch.setattr(
        CleanVulBenchmarkService, "_scan_repository_for_entry", _scan_repository_for_entry
    )

    service = _make_service(tmp_path)
    main_path, _ = service.build()

    payload = json.loads(main_path.read_text(encoding="utf-8"))
    assert [s["label"] for s in payload["samples"]] == [1, 0]
    assert payload["metadata"]["total_samples"] == 2

    # Verify CleanVul-specific metadata alias
    for sample in payload["samples"]:
        assert sample["metadata"]["commit_url"] == _COMMIT_URL


# ---------------------------------------------------------------------------
# build — token budget exceeded
# ---------------------------------------------------------------------------


def test_build_skips_pairs_over_token_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pairs whose func_code exceeds the token budget should be skipped."""
    row = _make_row()
    long_code = "x = '" + ("a" * 400) + "'"
    pair = _make_pair(func_code_vulnerable=long_code, func_code_fixed=long_code)

    vulnerable_repo = tmp_path / "repos" / "vulnerable"
    fixed_repo = tmp_path / "repos" / "fixed"
    vulnerable_repo.mkdir(parents=True)
    fixed_repo.mkdir(parents=True)

    def _fetch_entries(
        self: CleanVulLoaderService,
    ) -> list[tuple[list[CleanVulRow], str, str]]:
        del self
        return [([row], "https://github.com/owner/repo", "abcdef123456")]

    def _checkout_repo(
        self: RepoCheckoutService, repo_url: str, fix_hash: str, is_vulnerable: bool
    ) -> Path:
        del self, repo_url, fix_hash
        return vulnerable_repo if is_vulnerable else fixed_repo

    def _build_entry_pair(self: CleanVulBenchmarkService, **kwargs: object) -> _CleanVulEntryPair:
        del self, kwargs
        return pair

    scan_calls = {"count": 0}

    def _scan_repository_for_entry(
        self: CleanVulBenchmarkService, **kwargs: object
    ) -> dict[str, Context]:
        del self, kwargs
        scan_calls["count"] += 1
        return {}

    monkeypatch.setattr(CleanVulLoaderService, "fetch_entries", _fetch_entries)
    monkeypatch.setattr(RepoCheckoutService, "checkout_repo", _checkout_repo)
    monkeypatch.setattr(CleanVulBenchmarkService, "_build_entry_pair", _build_entry_pair)
    monkeypatch.setattr(
        CleanVulBenchmarkService, "_scan_repository_for_entry", _scan_repository_for_entry
    )

    service = _make_service(tmp_path, token_budget=10)
    main_path, _ = service.build()

    assert scan_calls["count"] == 0

    payload = json.loads(main_path.read_text(encoding="utf-8"))
    assert payload["samples"] == []


# ---------------------------------------------------------------------------
# build — KeyboardInterrupt writes partial datasets
# ---------------------------------------------------------------------------


def test_build_writes_partial_datasets_on_keyboard_interrupt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Partial datasets should be written before propagating KeyboardInterrupt."""
    row1 = _make_row()
    row2 = _make_row(commit_url="https://github.com/owner/repo/commit/deadbeef")
    pair1 = _make_pair()
    pair2 = _make_pair(func_code_vulnerable="def bar():\n    evil()")

    vulnerable_repo = tmp_path / "repos" / "vulnerable"
    fixed_repo = tmp_path / "repos" / "fixed"
    vulnerable_repo.mkdir(parents=True)
    fixed_repo.mkdir(parents=True)

    call_count = {"n": 0}

    def _fetch_entries_impl(
        self: CleanVulLoaderService,
    ) -> list[tuple[list[CleanVulRow], str, str]]:
        del self
        return [
            ([row1], "https://github.com/owner/repo", "abcdef123456"),
            ([row2], "https://github.com/owner/repo", "deadbeef"),
        ]

    def _checkout_repo(
        self: RepoCheckoutService, repo_url: str, fix_hash: str, is_vulnerable: bool
    ) -> Path:
        del self, repo_url, fix_hash
        return vulnerable_repo if is_vulnerable else fixed_repo

    def _build_entry_pair(
        self: CleanVulBenchmarkService,
        rows: list[CleanVulRow],
        **kwargs: object,
    ) -> _CleanVulEntryPair:
        del self, rows, kwargs
        call_count["n"] += 1
        if call_count["n"] == 1:
            return pair1
        return pair2

    def _scan_repository_for_entry(
        self: CleanVulBenchmarkService,
        repo_path: Path,
        entry: CleanVulEntry,
        strategy_factories: dict[str, object],
    ) -> dict[str, Context]:
        del self, repo_path
        if entry.func_code.startswith("def bar"):
            raise KeyboardInterrupt()
        return {
            strategy_name: Context(
                description=strategy_name,
                context_text=f"{'vuln' if entry.is_vulnerable else 'fixed'}-ctx",
                token_count=10,
            )
            for strategy_name in strategy_factories
        }

    monkeypatch.setattr(CleanVulLoaderService, "fetch_entries", _fetch_entries_impl)
    monkeypatch.setattr(RepoCheckoutService, "checkout_repo", _checkout_repo)
    monkeypatch.setattr(CleanVulBenchmarkService, "_build_entry_pair", _build_entry_pair)
    monkeypatch.setattr(
        CleanVulBenchmarkService, "_scan_repository_for_entry", _scan_repository_for_entry
    )

    service = _make_service(tmp_path, sample_count=4)

    with pytest.raises(KeyboardInterrupt):
        service.build()

    dataset_path = tmp_path / "output" / "cleanvul_context_benchmark.json"

    dataset_payload = json.loads(dataset_path.read_text(encoding="utf-8"))

    # First pair's samples were written before the interrupt
    assert len(dataset_payload["samples"]) == 2
    assert [s["label"] for s in dataset_payload["samples"]] == [1, 0]


# ---------------------------------------------------------------------------
# build — separate checkout roots
# ---------------------------------------------------------------------------


def test_build_uses_separate_checkout_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vulnerable and fixed checkouts should use different repo_cache_dir subdirs."""
    row = _make_row()
    pair = _make_pair()

    seen_cache_dirs: list[Path] = []

    def _fetch_entries(
        self: CleanVulLoaderService,
    ) -> list[tuple[list[CleanVulRow], str, str]]:
        del self
        return [([row], "https://github.com/owner/repo", "abcdef123456")]

    def _checkout_repo(
        self: RepoCheckoutService, repo_url: str, fix_hash: str, is_vulnerable: bool
    ) -> Path:
        del repo_url, fix_hash, is_vulnerable
        seen_cache_dirs.append(self.cache_dir)
        fake = self.cache_dir / "repo"
        fake.mkdir(parents=True, exist_ok=True)
        return fake

    def _build_entry_pair(self: CleanVulBenchmarkService, **kwargs: object) -> _CleanVulEntryPair:
        del self, kwargs
        return pair

    def _scan_repository_for_entry(
        self: CleanVulBenchmarkService,
        repo_path: Path,
        entry: CleanVulEntry,
        strategy_factories: dict[str, object],
    ) -> dict[str, Context]:
        del self, repo_path
        return {
            sn: Context(description=sn, context_text="ctx", token_count=5)
            for sn in strategy_factories
        }

    monkeypatch.setattr(CleanVulLoaderService, "fetch_entries", _fetch_entries)
    monkeypatch.setattr(RepoCheckoutService, "checkout_repo", _checkout_repo)
    monkeypatch.setattr(CleanVulBenchmarkService, "_build_entry_pair", _build_entry_pair)
    monkeypatch.setattr(
        CleanVulBenchmarkService, "_scan_repository_for_entry", _scan_repository_for_entry
    )

    service = _make_service(tmp_path)
    service.build()

    # Two checkouts: vulnerable and fixed, each with a different cache_dir
    assert len(seen_cache_dirs) == 2
    assert seen_cache_dirs[0] != seen_cache_dirs[1]
    # Both cache dirs are subdirectories of repo_cache_dir
    for d in seen_cache_dirs:
        assert d.parent == tmp_path / "repos"


def test_build_skips_repositories_over_size_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checked-out repositories larger than the configured limit should be skipped."""

    row = _make_row()
    pair = _make_pair()

    vulnerable_repo = tmp_path / "repos" / "vulnerable"
    fixed_repo = tmp_path / "repos" / "fixed"
    vulnerable_repo.mkdir(parents=True)
    fixed_repo.mkdir(parents=True)
    (vulnerable_repo / "big.py").write_text("x" * 128, encoding="utf-8")
    (fixed_repo / "big.py").write_text("x" * 128, encoding="utf-8")

    def _fetch_entries(
        self: CleanVulLoaderService,
    ) -> list[tuple[list[CleanVulRow], str, str]]:
        del self
        return [([row], "https://github.com/owner/repo", "abcdef123456")]

    def _checkout_repo(
        self: RepoCheckoutService, repo_url: str, fix_hash: str, is_vulnerable: bool
    ) -> Path:
        del self, repo_url, fix_hash
        return vulnerable_repo if is_vulnerable else fixed_repo

    def _build_entry_pair(self: CleanVulBenchmarkService, **kwargs: object) -> _CleanVulEntryPair:
        del self, kwargs
        return pair

    scan_calls = {"count": 0}

    def _scan_repository_for_entry(
        self: CleanVulBenchmarkService, **kwargs: object
    ) -> dict[str, Context]:
        del self, kwargs
        scan_calls["count"] += 1
        return {}

    monkeypatch.setattr(CleanVulLoaderService, "fetch_entries", _fetch_entries)
    monkeypatch.setattr(RepoCheckoutService, "checkout_repo", _checkout_repo)
    monkeypatch.setattr(CleanVulBenchmarkService, "_build_entry_pair", _build_entry_pair)
    monkeypatch.setattr(
        CleanVulBenchmarkService, "_scan_repository_for_entry", _scan_repository_for_entry
    )

    service = _make_service(tmp_path, max_repo_size_bytes=64)
    main_path, _ = service.build()

    assert scan_calls["count"] == 0

    payload = json.loads(main_path.read_text(encoding="utf-8"))
    assert payload["samples"] == []
