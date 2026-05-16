import csv
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class CleanVulRow(BaseModel):
    """Raw row from the CleanVul dataset after type coercion."""

    func_before: str
    func_after: str
    commit_url: str
    file_name: str
    cve_id: str = ""
    cwe_id: str = ""
    vulnerability_score: int = 0
    extension: str = ""
    is_test: bool = False
    commit_msg: str = ""


class CleanVulLoaderService(BaseModel):
    """Load and filter CleanVul entries from a local CSV or Parquet file."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    dataset_path: Path = Field(..., description="Path to the CleanVul CSV or Parquet file")
    min_score: int = Field(
        default=3, ge=0, le=4, description="Minimum vulnerability_score to include"
    )

    def fetch_entries(self) -> list[tuple[list[CleanVulRow], str, str]]:
        """Load and filter rows from the dataset, grouped by commit.

        Multiple rows from the same commit (same repo + fix hash) are merged
        into a single group so that all modified functions are processed together
        in one repository checkout.

        Returns:
            List of (rows_for_commit, repo_url, fix_hash) tuples, one per unique commit.
        """
        raw_rows = self._load_rows()
        # Preserve insertion order so shuffling in the benchmark service is deterministic
        groups: dict[tuple[str, str], list[CleanVulRow]] = {}

        for raw in raw_rows:
            row = self._coerce_row(raw)

            if row.extension != "py":
                continue
            if row.is_test:
                continue
            if row.vulnerability_score < self.min_score:
                continue

            commit_url = row.commit_url.strip()
            if not commit_url:
                continue

            try:
                repo_url, fix_hash = self._parse_commit_url(commit_url)
            except ValueError:
                logger.warning("Skipping unrecognised commit URL: %r", commit_url)
                continue

            if not row.func_before.strip() or not row.func_after.strip():
                continue
            if row.func_before.strip() == row.func_after.strip():
                continue

            key = (repo_url, fix_hash)
            if key not in groups:
                groups[key] = []
            groups[key].append(row)

        return [(rows, repo_url, fix_hash) for (repo_url, fix_hash), rows in groups.items()]

    @staticmethod
    def _parse_commit_url(commit_url: str) -> tuple[str, str]:
        """Extract (repo_url, fix_hash) from a GitHub commit URL.

        Parses ``https://github.com/owner/repo/commit/HASH`` into
        ``('https://github.com/owner/repo', 'HASH')``.

        Args:
            commit_url: Full URL to the fixing commit.

        Returns:
            Tuple of (repo_url, fix_hash).

        Raises:
            ValueError: When the URL does not match the expected pattern.
        """
        parsed = urlparse(commit_url)
        path_parts = parsed.path.strip("/").split("/")

        # Expected shape: ["owner", "repo", "commit", "HASH"]
        if len(path_parts) < 4 or path_parts[-2] != "commit":
            raise ValueError(f"Unrecognised commit URL (expected .../commit/HASH): {commit_url!r}")

        fix_hash = path_parts[-1]
        repo_path = "/".join(path_parts[:-2])
        repo_url = f"{parsed.scheme}://{parsed.netloc}/{repo_path}"
        return repo_url, fix_hash

    @staticmethod
    def _parse_cwe_ids(cwe_text: str) -> list[int]:
        """Extract all numeric CWE identifiers from freeform text.

        Handles formats like ``'CWE-79'``, ``"['CWE-79', 'CWE-89']"``, ``'79'``.

        Args:
            cwe_text: Raw CWE field value from the dataset.

        Returns:
            Deduplicated list of numeric CWE identifiers in order of first appearance.
        """
        if not cwe_text or not cwe_text.strip():
            return []

        # Prefer explicit CWE-NNN patterns (most reliable)
        cwe_pattern = re.compile(r"CWE-(\d+)", re.IGNORECASE)
        matches = cwe_pattern.findall(cwe_text)
        if matches:
            seen: set[int] = set()
            result: list[int] = []
            for m in matches:
                val = int(m)
                if val not in seen:
                    seen.add(val)
                    result.append(val)
            return result

        # Fall back: strip non-digit characters and treat remaining digits as one id
        digits_only = re.sub(r"[^\d]", "", cwe_text)
        if digits_only:
            return [int(digits_only)]
        return []

    def _load_rows(self) -> list[dict[str, Any]]:
        """Load raw rows from CSV or Parquet depending on file extension.

        Returns:
            List of raw row dictionaries.

        Raises:
            ImportError: When loading Parquet without pandas/pyarrow installed.
            ValueError: When the file extension is not supported.
        """
        suffix = self.dataset_path.suffix.lower()

        if suffix == ".parquet":
            try:
                import pandas as pd  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ImportError(
                    "pandas is required to load Parquet files. "
                    "Install it with: uv add pandas pyarrow"
                ) from exc
            df = pd.read_parquet(self.dataset_path)
            return df.to_dict("records")

        if suffix in (".csv", ".tsv"):
            with open(self.dataset_path, encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                return list(reader)

        raise ValueError(f"Unsupported file extension: {suffix!r}. Use .csv, .tsv, or .parquet")

    @staticmethod
    def _coerce_row(raw: dict[str, Any]) -> CleanVulRow:
        """Coerce a raw dictionary into a CleanVulRow, handling CSV string types.

        CSV files represent all values as strings; this method normalises booleans
        and integers before validation.

        Args:
            raw: Raw row dictionary from the dataset.

        Returns:
            Validated CleanVulRow instance.
        """

        def _str(key: str) -> str:
            v = raw.get(key, "")
            return str(v) if v is not None else ""

        def _int(key: str) -> int:
            v = raw.get(key, 0)
            if v is None:
                return 0
            try:
                return int(str(v))
            except (TypeError, ValueError):
                return 0

        def _bool(key: str) -> bool:
            v = raw.get(key, False)
            if isinstance(v, bool):
                return v
            return str(v).strip().lower() in ("true", "1", "yes")

        return CleanVulRow(
            func_before=_str("func_before"),
            func_after=_str("func_after"),
            commit_url=_str("commit_url"),
            file_name=_str("file_name"),
            cve_id=_str("cve_id"),
            cwe_id=_str("cwe_id"),
            vulnerability_score=_int("vulnerability_score"),
            extension=_str("extension"),
            is_test=_bool("is_test"),
            commit_msg=_str("commit_msg"),
        )
