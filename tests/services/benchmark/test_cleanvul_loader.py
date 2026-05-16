"""Tests for the CleanVul dataset loader."""

from pathlib import Path

import pytest

from services.benchmark.cleanvul_loader import CleanVulLoaderService


def _make_row(**overrides: object) -> dict[str, object]:
    """Build a minimal valid raw row dict."""
    base: dict[str, object] = {
        "func_before": "def foo():\n    pass",
        "func_after": "def foo():\n    return 1",
        "commit_url": "https://github.com/owner/repo/commit/abc123",
        "file_name": "src/foo.py",
        "cve_id": "CVE-2024-0001",
        "cwe_id": "CWE-79",
        "vulnerability_score": "3",
        "extension": "py",
        "is_test": "False",
        "commit_msg": "fix: patch XSS",
    }
    base.update(overrides)
    return base


def _make_service(**overrides: object) -> CleanVulLoaderService:
    defaults: dict[str, object] = {"dataset_path": Path("/tmp/cleanvul.csv")}
    defaults.update(overrides)
    return CleanVulLoaderService(**defaults)


# ---------------------------------------------------------------------------
# fetch_entries filtering
# ---------------------------------------------------------------------------


def test_fetch_entries_filters_by_extension(monkeypatch: pytest.MonkeyPatch) -> None:
    """python_only=True should drop non-py rows."""
    rows = [
        _make_row(extension="py"),
        _make_row(extension="js"),
        _make_row(extension="java"),
    ]
    service = _make_service(python_only=True)
    monkeypatch.setattr(service, "_load_rows", lambda: rows)

    results = service.fetch_entries()

    assert len(results) == 1
    assert results[0][0][0].extension == "py"


def test_fetch_entries_filters_by_score(monkeypatch: pytest.MonkeyPatch) -> None:
    """min_score=3 should keep only rows with score >= 3."""
    rows = [
        _make_row(
            vulnerability_score="1",
            commit_url="https://github.com/owner/repo/commit/aaa111",
        ),
        _make_row(
            vulnerability_score="2",
            commit_url="https://github.com/owner/repo/commit/bbb222",
        ),
        _make_row(
            vulnerability_score="3",
            commit_url="https://github.com/owner/repo/commit/ccc333",
        ),
        _make_row(
            vulnerability_score="4",
            commit_url="https://github.com/owner/repo/commit/ddd444",
        ),
    ]
    service = _make_service(min_score=3)
    monkeypatch.setattr(service, "_load_rows", lambda: rows)

    results = service.fetch_entries()

    assert len(results) == 2
    scores = [r[0][0].vulnerability_score for r in results]
    assert scores == [3, 4]


def test_fetch_entries_excludes_test_files(monkeypatch: pytest.MonkeyPatch) -> None:
    """exclude_test_files=True should drop rows where is_test is truthy."""
    rows = [
        _make_row(is_test="True"),
        _make_row(is_test="False"),
        _make_row(is_test="1"),
    ]
    service = _make_service(exclude_test_files=True)
    monkeypatch.setattr(service, "_load_rows", lambda: rows)

    results = service.fetch_entries()

    assert len(results) == 1
    assert results[0][0][0].is_test is False


def test_fetch_entries_skips_invalid_commit_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rows with unparseable commit URLs should be skipped, not raise."""
    rows = [
        _make_row(commit_url="https://github.com/owner/repo"),  # missing /commit/
        _make_row(commit_url="not-a-url"),
        _make_row(),  # valid row
    ]
    service = _make_service()
    monkeypatch.setattr(service, "_load_rows", lambda: rows)

    results = service.fetch_entries()

    assert len(results) == 1


def test_fetch_entries_skips_empty_func(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rows with blank func_before or func_after should be skipped."""
    rows = [
        _make_row(func_before=""),
        _make_row(func_after="   "),
        _make_row(),  # valid
    ]
    service = _make_service()
    monkeypatch.setattr(service, "_load_rows", lambda: rows)

    results = service.fetch_entries()

    assert len(results) == 1


def test_fetch_entries_skips_identical_before_after(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rows where func_before and func_after are identical should be skipped."""
    same = "def foo():\n    pass"
    rows = [
        _make_row(func_before=same, func_after=same),
        _make_row(),  # valid (different before/after)
    ]
    service = _make_service()
    monkeypatch.setattr(service, "_load_rows", lambda: rows)

    results = service.fetch_entries()

    assert len(results) == 1


# ---------------------------------------------------------------------------
# _parse_commit_url
# ---------------------------------------------------------------------------


def test_parse_commit_url_standard() -> None:
    """Standard GitHub commit URL should parse into (repo_url, fix_hash)."""
    repo_url, fix_hash = CleanVulLoaderService._parse_commit_url(
        "https://github.com/owner/repo/commit/abc123def456"
    )
    assert repo_url == "https://github.com/owner/repo"
    assert fix_hash == "abc123def456"


def test_parse_commit_url_nested_repo() -> None:
    """Org/repo paths with multiple components should be handled correctly."""
    repo_url, fix_hash = CleanVulLoaderService._parse_commit_url(
        "https://github.com/myorg/my-repo/commit/deadbeef"
    )
    assert repo_url == "https://github.com/myorg/my-repo"
    assert fix_hash == "deadbeef"


def test_parse_commit_url_raises_on_missing_commit_segment() -> None:
    """URLs without a /commit/ segment should raise ValueError."""
    with pytest.raises(ValueError, match="commit"):
        CleanVulLoaderService._parse_commit_url("https://github.com/owner/repo")


def test_parse_commit_url_raises_on_non_commit_url() -> None:
    """Non-commit GitHub URLs should raise ValueError."""
    with pytest.raises(ValueError):
        CleanVulLoaderService._parse_commit_url("https://github.com/owner/repo/pull/42")


# ---------------------------------------------------------------------------
# _parse_cwe_ids
# ---------------------------------------------------------------------------


def test_parse_cwe_ids_single_prefix() -> None:
    assert CleanVulLoaderService._parse_cwe_ids("CWE-79") == [79]


def test_parse_cwe_ids_case_insensitive() -> None:
    assert CleanVulLoaderService._parse_cwe_ids("cwe-89") == [89]


def test_parse_cwe_ids_list_format() -> None:
    assert CleanVulLoaderService._parse_cwe_ids("['CWE-79', 'CWE-89']") == [79, 89]


def test_parse_cwe_ids_bare_number() -> None:
    assert CleanVulLoaderService._parse_cwe_ids("79") == [79]


def test_parse_cwe_ids_empty() -> None:
    assert CleanVulLoaderService._parse_cwe_ids("") == []


def test_parse_cwe_ids_whitespace_only() -> None:
    assert CleanVulLoaderService._parse_cwe_ids("   ") == []


def test_parse_cwe_ids_deduplicates() -> None:
    assert CleanVulLoaderService._parse_cwe_ids("CWE-79 CWE-79 CWE-79") == [79]


def test_parse_cwe_ids_multiple_unique() -> None:
    result = CleanVulLoaderService._parse_cwe_ids("CWE-20 CWE-79 CWE-89")
    assert result == [20, 79, 89]


def test_parse_cwe_ids_preserves_order() -> None:
    result = CleanVulLoaderService._parse_cwe_ids("CWE-89 CWE-20")
    assert result == [89, 20]


# ---------------------------------------------------------------------------
# _load_rows
# ---------------------------------------------------------------------------


def test_load_rows_raises_on_unsupported_extension(tmp_path: Path) -> None:
    """An unsupported file extension should raise ValueError."""
    bad_path = tmp_path / "data.xlsx"
    bad_path.write_text("", encoding="utf-8")
    service = _make_service(dataset_path=bad_path)

    with pytest.raises(ValueError, match=r"\.xlsx"):
        service._load_rows()


def test_load_rows_csv(tmp_path: Path) -> None:
    """CSV files should be loaded via stdlib csv.DictReader."""
    csv_path = tmp_path / "data.csv"
    csv_path.write_text(
        "func_before,func_after,commit_url,file_name,cve_id,cwe_id,"
        "vulnerability_score,extension,is_test,commit_msg\n"
        "def foo():,def bar():,https://github.com/o/r/commit/abc,foo.py,"
        "CVE-2024-0001,CWE-79,3,py,False,fix\n",
        encoding="utf-8",
    )
    service = _make_service(dataset_path=csv_path)

    rows = service._load_rows()

    assert len(rows) == 1
    assert rows[0]["func_before"] == "def foo():"
