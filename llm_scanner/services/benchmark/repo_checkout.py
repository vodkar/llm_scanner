from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class RepoCheckoutService(BaseModel):
    """Clone and checkout repositories at vulnerable commits."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    cache_dir: Path = Field(..., description="Directory to store cloned repositories")
    git_executable: str = Field(default="git", description="Git executable to use")

    def checkout_vulnerable_repo(self, repo_url: str, fix_hash: str) -> Path:
        """Ensure repository is cloned and checked out to vulnerable commit.

        Args:
            repo_url: Repository URL.
            fix_hash: Fix commit hash.

        Returns:
            Path to the checked-out repository.
        """

        repo_path = self._repo_path_for_url(repo_url)
        if not repo_path.exists():
            self._clone_repo(repo_url, repo_path)
        else:
            self._fetch_repo(repo_path)

        parent_hash = self._resolve_parent_hash(repo_path, fix_hash)
        self._checkout_commit(repo_path, parent_hash)
        return repo_path

    def _repo_path_for_url(self, repo_url: str) -> Path:
        parsed = urlparse(repo_url)
        path = parsed.path.strip("/")
        if path.endswith(".git"):
            path = path[:-4]
        if not path:
            raise ValueError(f"Invalid repo URL: {repo_url}")
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", path)
        return self.cache_dir / safe_name

    def _clone_repo(self, repo_url: str, repo_path: Path) -> None:
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        self._run_git(["clone", "--quiet", repo_url, str(repo_path)])

    def _fetch_repo(self, repo_path: Path) -> None:
        self._run_git(["-C", str(repo_path), "fetch", "--all", "--tags", "--prune"])

    def _checkout_commit(self, repo_path: Path, commit_hash: str) -> None:
        self._run_git(["-C", str(repo_path), "checkout", "--quiet", commit_hash])

    def _resolve_parent_hash(self, repo_path: Path, fix_hash: str) -> str:
        output = self._run_git(["-C", str(repo_path), "rev-list", "--parents", "-n", "1", fix_hash])
        parts = output.strip().split()
        if len(parts) < 2:
            raise ValueError(f"No parent found for commit {fix_hash}")
        return parts[1]

    def _run_git(self, args: list[str]) -> str:
        try:
            result = subprocess.run(
                [self.git_executable, *args],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            logger.exception("Git command failed: %s", " ".join([self.git_executable, *args]))
            raise RuntimeError(exc.stderr.strip() or str(exc)) from exc
        return result.stdout
