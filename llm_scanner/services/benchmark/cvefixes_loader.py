from __future__ import annotations

import logging
import random
import sqlite3
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from models.benchmark.cvefixes import CVEFixesEntry

logger = logging.getLogger(__name__)


class CVEFixesLoaderService(BaseModel):
    """Load and sample CVEFixes entries from the SQLite dataset."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    db_path: Path = Field(..., description="Path to the CVEFixes SQLite database")

    def fetch_python_entries(self) -> list[CVEFixesEntry]:
        """Load Python vulnerability entries with location data.

        Returns:
            List of normalized CVEFixes entries.
        """

        rows = self._fetch_candidate_rows()
        entries: list[CVEFixesEntry] = []
        seen: set[tuple[str, str, str, str, int, int]] = set()

        for row in rows:
            before_change = self._parse_bool(self._get_row_value(row, "before_change"))
            if before_change is False:
                continue

            start_line = self._parse_int(self._get_row_value(row, "start_line"))
            end_line = self._parse_int(self._get_row_value(row, "end_line"))
            if start_line is None or end_line is None:
                continue

            file_path = self._normalize_file_path(
                self._get_row_value(row, "old_path"),
                self._get_row_value(row, "new_path"),
                self._get_row_value(row, "filename"),
            )
            if file_path is None:
                continue

            cwe_id = self._parse_cwe_id(self._get_row_value(row, "cwe_id"))
            severity = self._normalize_severity(
                self._get_row_value(row, "cvss3_base_severity"),
                self._get_row_value(row, "severity"),
            )

            cve_id = str(self._get_row_value(row, "cve_id") or "").strip()
            repo_url = str(self._get_row_value(row, "repo_url") or "").strip()
            fix_hash = str(self._get_row_value(row, "fix_hash") or "").strip()
            description = str(self._get_row_value(row, "description") or "").strip()

            if not cve_id or not repo_url or not fix_hash:
                continue

            dedupe_key = (
                cve_id,
                repo_url,
                fix_hash,
                file_path.as_posix(),
                start_line,
                end_line,
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            entries.append(
                CVEFixesEntry(
                    cve_id=cve_id,
                    repo_url=repo_url,
                    fix_hash=fix_hash,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    description=description,
                    cwe_id=cwe_id,
                    severity=severity,
                )
            )

        return entries

    def sample_entries(
        self, entries: list[CVEFixesEntry], sample_count: int, seed: int | None
    ) -> list[CVEFixesEntry]:
        """Randomly sample entries.

        Args:
            entries: Candidate CVEFixes entries.
            sample_count: Number of samples to select.
            seed: Optional random seed.

        Returns:
            Randomly sampled entries.
        """

        if sample_count <= 0:
            return []
        if sample_count > len(entries):
            raise ValueError(f"Requested {sample_count} samples but only {len(entries)} available")

        rng = random.Random(seed)
        return rng.sample(entries, sample_count)

    def _fetch_candidate_rows(self) -> list[sqlite3.Row]:
        query = (
            "SELECT f.cve_id AS cve_id, f.hash AS fix_hash, f.repo_url AS repo_url, "
            "fc.filename AS filename, fc.old_path AS old_path, fc.new_path AS new_path, "
            "mc.start_line AS start_line, mc.end_line AS end_line, "
            "mc.before_change AS before_change, "
            "c.description AS description, c.cvss3_base_severity AS cvss3_base_severity, "
            "c.severity AS severity, cc.cwe_id AS cwe_id "
            "FROM fixes f "
            "JOIN file_change fc ON fc.hash = f.hash "
            "LEFT JOIN method_change mc ON mc.file_change_id = fc.file_change_id "
            "LEFT JOIN cve c ON c.cve_id = f.cve_id "
            "LEFT JOIN cwe_classification cc ON cc.cve_id = f.cve_id "
            "WHERE fc.programming_language = 'Python'"
        )

        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            cursor = connection.execute(query)
            return cursor.fetchall()
        finally:
            connection.close()

    @staticmethod
    def _get_row_value(row: sqlite3.Row, key: str) -> object | None:
        try:
            return row[key]
        except (KeyError, IndexError):
            return None

    @staticmethod
    def _parse_int(value: object | None) -> int | None:
        if value is None:
            return None
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_bool(value: object | None) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in {"true", "1", "yes"}:
            return True
        if text in {"false", "0", "no"}:
            return False
        return None

    @staticmethod
    def _parse_cwe_id(value: object | None) -> int | None:
        if value is None:
            return None
        text = str(value).strip()
        if text.startswith("CWE-"):
            text = text[4:]
        if text.isdigit():
            return int(text)
        return None

    @staticmethod
    def _normalize_severity(*values: object | None) -> str | None:
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text.lower()
        return None

    @staticmethod
    def _normalize_file_path(
        old_path: object | None, new_path: object | None, filename: object | None
    ) -> Path | None:
        for candidate in (old_path, new_path, filename):
            if candidate is None:
                continue
            text = str(candidate).strip()
            if not text:
                continue
            return Path(text)
        return None
