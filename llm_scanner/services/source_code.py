import textwrap
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel


class SourceCodeService(BaseModel):
    """Service for working with source code content from repositories."""

    @staticmethod
    def find_function_line_span(
        file_path: Path,
        func_code: str,
    ) -> tuple[int, int] | None:
        """Locate ``func_code`` in a file by text matching.

        Tries three increasingly lenient matching strategies in order:

        1. Exact match (rstrip each line; skip blank file lines while scanning).
        2. Whitespace-normalised match (collapse all runs of whitespace).
        3. Dedented match (``textwrap.dedent`` the needle, then whitespace-normalise).

        Args:
            file_path: Path to the source file in the checked-out repository.
            func_code: Function source text from the dataset.

        Returns:
            1-based ``(start_line, end_line)`` tuple, or ``None`` if not found.
        """
        try:
            file_text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

        file_lines = file_text.splitlines()

        def _rstrip_needle(code: str) -> list[str]:
            return [ln.rstrip() for ln in code.splitlines() if ln.strip()]

        def _normalise(line: str) -> str:
            return " ".join(line.split())

        def _normalise_needle(code: str) -> list[str]:
            return [_normalise(ln) for ln in code.splitlines() if ln.strip()]

        def _search(
            needle_lines: list[str], transform: Callable[[str], str]
        ) -> tuple[int, int] | None:
            if not needle_lines:
                return None
            first = needle_lines[0]
            for i, file_line in enumerate(file_lines):
                if transform(file_line) != first:
                    continue
                # Candidate start at file line i
                candidate_end = i
                needle_idx = 1
                j = i + 1
                while needle_idx < len(needle_lines) and j < len(file_lines):
                    file_transformed = transform(file_lines[j])
                    if file_transformed == needle_lines[needle_idx]:
                        needle_idx += 1
                        candidate_end = j
                    elif file_transformed == "":
                        pass  # skip blank file lines not in needle
                    else:
                        break  # mismatch
                    j += 1
                if needle_idx == len(needle_lines):
                    return (i + 1, candidate_end + 1)  # 1-based
            return None

        # Tier 1: exact (rstrip)
        result = _search(_rstrip_needle(func_code), str.rstrip)
        if result is not None:
            return result

        # Tier 2: whitespace-normalised
        result = _search(_normalise_needle(func_code), _normalise)
        if result is not None:
            return result

        # Tier 3: dedented + whitespace-normalised
        dedented = textwrap.dedent(func_code)
        result = _search(_normalise_needle(dedented), _normalise)
        return result
