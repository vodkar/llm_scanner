from pathlib import Path
from threading import Lock
from typing import cast

from pydantic import BaseModel, ConfigDict, PrivateAttr


class SnippetReaderService(BaseModel):
    """Read and cache source snippets for ranking heuristics."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    project_root: Path
    cache_max_entries: int = 10000

    _cache_lock: Lock = PrivateAttr(default_factory=Lock)
    _file_lines_cache: dict[Path, list[str]] = PrivateAttr(
        default_factory=lambda: cast(dict[Path, list[str]], {})
    )
    _snippet_cache: dict[tuple[Path, int, int], str] = PrivateAttr(
        default_factory=lambda: cast(dict[tuple[Path, int, int], str], {})
    )

    def read_snippet(self, file_path: Path, line_start: int | None, line_end: int | None) -> str:
        """Read a code snippet for the given file and line range."""

        if line_start is None or line_end is None or line_start < 1 or line_end < line_start:
            return ""

        absolute_path = (self.project_root / file_path).resolve()
        if not absolute_path.exists():
            return ""

        snippet_key = (absolute_path, line_start, line_end)

        with self._cache_lock:
            cached_snippet = self._snippet_cache.get(snippet_key)
        if cached_snippet is not None:
            return cached_snippet

        with self._cache_lock:
            lines = self._file_lines_cache.get(absolute_path)

        if lines is None:
            with absolute_path.open("r", encoding="utf-8", errors="ignore") as handle:
                lines = handle.readlines()
            with self._cache_lock:
                self._file_lines_cache[absolute_path] = lines

        start_index = max(line_start - 1, 0)
        end_index = min(line_end, len(lines))
        snippet = "".join(lines[start_index:end_index]).rstrip()

        with self._cache_lock:
            if len(self._snippet_cache) >= self.cache_max_entries:
                self._snippet_cache.clear()
            self._snippet_cache[snippet_key] = snippet

        return snippet
