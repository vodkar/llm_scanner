from pathlib import Path

from services.benchmark.repo_checkout import RepoCheckoutService


def test_checkout_repo_uses_parent_for_vulnerable(monkeypatch) -> None:
    service = RepoCheckoutService(cache_dir=Path("/tmp/cache"))
    repo_path = Path("/tmp/cache/owner_repo")

    monkeypatch.setattr(service, "_repo_path_for_url", lambda _repo_url: repo_path)
    monkeypatch.setattr(Path, "exists", lambda self: True)

    fetch_calls: list[Path] = []
    checkout_calls: list[tuple[Path, str]] = []

    monkeypatch.setattr(service, "_fetch_repo", lambda path: fetch_calls.append(path))
    monkeypatch.setattr(service, "_clone_repo", lambda repo_url, path: None)
    monkeypatch.setattr(service, "_resolve_parent_hash", lambda path, fix_hash: "parent123")
    monkeypatch.setattr(
        service,
        "_checkout_commit",
        lambda path, commit_hash: checkout_calls.append((path, commit_hash)),
    )

    result = service.checkout_repo(
        repo_url="https://example.com/owner/repo.git",
        fix_hash="fix123",
        is_vulnerable=True,
    )

    assert result == repo_path
    assert fetch_calls == [repo_path]
    assert checkout_calls == [(repo_path, "parent123")]


def test_checkout_repo_uses_fix_hash_for_non_vulnerable(monkeypatch) -> None:
    service = RepoCheckoutService(cache_dir=Path("/tmp/cache"))
    repo_path = Path("/tmp/cache/owner_repo")

    monkeypatch.setattr(service, "_repo_path_for_url", lambda _repo_url: repo_path)
    monkeypatch.setattr(Path, "exists", lambda self: True)

    fetch_calls: list[Path] = []
    checkout_calls: list[tuple[Path, str]] = []
    parent_resolution_called = {"value": False}

    monkeypatch.setattr(service, "_fetch_repo", lambda path: fetch_calls.append(path))
    monkeypatch.setattr(service, "_clone_repo", lambda repo_url, path: None)

    def _unexpected_parent_resolution(path: Path, fix_hash: str) -> str:
        parent_resolution_called["value"] = True
        return "parent123"

    monkeypatch.setattr(service, "_resolve_parent_hash", _unexpected_parent_resolution)
    monkeypatch.setattr(
        service,
        "_checkout_commit",
        lambda path, commit_hash: checkout_calls.append((path, commit_hash)),
    )

    result = service.checkout_repo(
        repo_url="https://example.com/owner/repo.git",
        fix_hash="fix123",
        is_vulnerable=False,
    )

    assert result == repo_path
    assert fetch_calls == [repo_path]
    assert checkout_calls == [(repo_path, "fix123")]
    assert not parent_resolution_called["value"]
