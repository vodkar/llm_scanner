import ast
import json
import logging
import sqlite3
from collections import defaultdict
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from models.benchmark.cvefixes import CVEFixesEntry
from models.context import FileSpans

logger = logging.getLogger(__name__)


class _EntryAccumulator(BaseModel):
    """Collect spans and metadata for one normalized CVEFixes entry."""

    cve_id: str
    repo_url: str
    fix_hash: str
    is_vulnerable: bool
    description: str = ""
    cwe_id: int | None = None
    severity: str | None = None
    file_spans: dict[Path, set[tuple[int, int]]] = Field(
        default_factory=lambda: defaultdict[Path, set[tuple[int, int]]](set)
    )

    model_config = ConfigDict(arbitrary_types_allowed=True)


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
        grouped: dict[tuple[str, str, str, bool], _EntryAccumulator] = {}

        for row in rows:
            diff_parsed = self._parse_diff_parsed(self._get_row_value(row, "diff_parsed"))
            if diff_parsed is None:
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

            for is_vulnerable in (True, False):
                line_spans = self._extract_diff_line_spans(diff_parsed, is_vulnerable)
                if not line_spans:
                    continue

                file_path = self._resolve_span_file_path(
                    is_vulnerable,
                    self._get_row_value(row, "old_path"),
                    self._get_row_value(row, "new_path"),
                    self._get_row_value(row, "filename"),
                )
                if file_path is None:
                    continue

                group_key = (cve_id, repo_url, fix_hash, is_vulnerable)
                if group_key not in grouped:
                    grouped[group_key] = _EntryAccumulator(
                        cve_id=cve_id,
                        repo_url=repo_url,
                        fix_hash=fix_hash,
                        is_vulnerable=is_vulnerable,
                    )

                accumulator = grouped[group_key]
                for start_line, end_line in line_spans:
                    accumulator.file_spans[file_path].add((start_line, end_line))

                if not accumulator.description and description:
                    accumulator.description = description
                if accumulator.cwe_id is None and cwe_id is not None:
                    accumulator.cwe_id = cwe_id
                if accumulator.severity is None and severity is not None:
                    accumulator.severity = severity

        entries: list[CVEFixesEntry] = []
        for key in sorted(grouped.keys()):
            accumulator = grouped[key]
            files_spans = [
                FileSpans(
                    file_path=file_path,
                    line_spans=self._merge_spans(spans),
                )
                for file_path, spans in sorted(
                    accumulator.file_spans.items(), key=lambda item: item[0].as_posix()
                )
            ]
            if not files_spans:
                continue
            entries.append(
                CVEFixesEntry(
                    cve_id=accumulator.cve_id,
                    repo_url=accumulator.repo_url,
                    fix_hash=accumulator.fix_hash,
                    files_spans=files_spans,
                    description=accumulator.description,
                    cwe_id=accumulator.cwe_id,
                    severity=accumulator.severity,
                    is_vulnerable=accumulator.is_vulnerable,
                )
            )

        return entries

    def _fetch_candidate_rows(self) -> list[sqlite3.Row]:
        query = (
            "SELECT f.cve_id AS cve_id, f.hash AS fix_hash, f.repo_url AS repo_url, "
            "fc.filename AS filename, fc.old_path AS old_path, fc.new_path AS new_path, "
            "fc.diff_parsed AS diff_parsed, "
            "c.description AS description, c.cvss3_base_severity AS cvss3_base_severity, "
            "c.severity AS severity, cc.cwe_id AS cwe_id "
            "FROM fixes f "
            "JOIN file_change fc ON fc.hash = f.hash "
            "LEFT JOIN cve c ON c.cve_id = f.cve_id "
            "LEFT JOIN cwe_classification cc ON cc.cve_id = f.cve_id "
            "WHERE fc.programming_language = 'Python' "
            "AND fc.diff_parsed IS NOT NULL"
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
    def _parse_cwe_id(value: object | None) -> int | None:
        if value is None:
            return None
        text = str(value).strip()
        if text.startswith("CWE-"):
            text = text[4:]
        if text.isdigit():
            return int(text)
        return None

    @classmethod
    def _parse_diff_parsed(cls, value: object | None) -> dict[str, object] | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value

        text = str(value).strip()
        if not text:
            return None

        try:
            parsed = ast.literal_eval(text)
            if isinstance(parsed, dict):
                return parsed
        except (SyntaxError, ValueError):
            pass

        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except (TypeError, ValueError):
            return None

        return None

    @classmethod
    def _extract_diff_line_spans(
        cls, diff_parsed: dict[str, object], is_vulnerable: bool
    ) -> list[tuple[int, int]]:
        key = "deleted" if is_vulnerable else "added"
        chunks = diff_parsed.get(key)
        if not isinstance(chunks, list):
            return []

        lines: list[int] = []
        for chunk in chunks:
            if isinstance(chunk, (list, tuple)) and chunk:
                parsed_line = cls._parse_int(chunk[0])
                if parsed_line is not None and parsed_line > 0:
                    lines.append(parsed_line)

        return cls._collapse_lines_to_spans(lines)

    @staticmethod
    def _collapse_lines_to_spans(lines: list[int]) -> list[tuple[int, int]]:
        if not lines:
            return []

        unique_sorted_lines = sorted(set(lines))
        spans: list[tuple[int, int]] = []

        span_start = unique_sorted_lines[0]
        span_end = unique_sorted_lines[0]
        for line in unique_sorted_lines[1:]:
            if line == span_end + 1:
                span_end = line
                continue
            spans.append((span_start, span_end))
            span_start = line
            span_end = line
        spans.append((span_start, span_end))

        return spans

    @staticmethod
    def _merge_spans(spans: set[tuple[int, int]]) -> list[tuple[int, int]]:
        if not spans:
            return []

        ordered = sorted(spans)
        merged: list[tuple[int, int]] = []

        current_start, current_end = ordered[0]
        for start, end in ordered[1:]:
            if start <= current_end + 1:
                current_end = max(current_end, end)
                continue
            merged.append((current_start, current_end))
            current_start, current_end = start, end

        merged.append((current_start, current_end))
        return merged

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
    def _resolve_span_file_path(
        is_vulnerable: bool,
        old_path: object | None,
        new_path: object | None,
        filename: object | None,
    ) -> Path | None:
        preferred = (
            (old_path, new_path, filename) if is_vulnerable else (new_path, old_path, filename)
        )
        for candidate in preferred:
            if candidate is None:
                continue
            text = str(candidate).strip()
            if not text:
                continue
            return Path(text)
        return None
