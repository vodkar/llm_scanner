"""Helpers mapping rendered snippet lines back to repository locations."""

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from models.context import SnippetSegment

type RenderedLine = tuple[Path, int, str]

# Characters ``str.splitlines()`` treats as line breaks but Python's tokenizer
# (and therefore Bandit, Dlint and the CPG) does not.
_NON_TOKENIZER_LINE_BREAKS: Final[frozenset[str]] = frozenset(
    "\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
)


def has_nonstandard_line_breaks(text: str) -> bool:
    """Return True when ``splitlines()`` numbering diverges from analyzer numbering.

    Args:
        text: Full source file text.

    Returns:
        True if the text contains a line-break character other than ``\\r``/``\\n``.
    """

    return any(char in _NON_TOKENIZER_LINE_BREAKS for char in text)


def build_source_map(rendered_lines: Sequence[RenderedLine]) -> list[SnippetSegment]:
    """Group rendered lines into per-file runs of consecutive snippet lines.

    Args:
        rendered_lines: ``(file_path, repo_line, text)`` in snippet order.

    Returns:
        Segments covering every rendered line exactly once, in snippet order.
    """

    segments: list[SnippetSegment] = []
    run_file: Path | None = None
    run_start = 1
    run_lines: list[int] = []
    for index, (file_path, repo_line, _) in enumerate(rendered_lines, start=1):
        if file_path != run_file and run_lines:
            segments.append(_segment(run_file, run_start, run_lines))
            run_lines = []
        if not run_lines:
            run_file = file_path
            run_start = index
        run_lines.append(repo_line)
    if run_lines:
        segments.append(_segment(run_file, run_start, run_lines))
    return segments


def resolve_snippet_line(
    source_map: Sequence[SnippetSegment], file_path: Path, repo_line: int
) -> int | None:
    """Return the 1-based snippet line showing ``file_path:repo_line``, if rendered.

    Args:
        source_map: Segments produced by ``build_source_map``.
        file_path: Repo-relative file path.
        repo_line: 1-based repository line.

    Returns:
        Snippet line number, or ``None`` when that repo line is not in the snippet.
    """

    for segment in source_map:
        if segment.file_path != file_path or repo_line not in segment.repo_lines:
            continue
        return segment.snippet_line_start + segment.repo_lines.index(repo_line)
    return None


def _segment(file_path: Path | None, start: int, repo_lines: list[int]) -> SnippetSegment:
    if file_path is None:
        raise ValueError("Cannot build a segment without a file path")
    return SnippetSegment(
        file_path=file_path,
        snippet_line_start=start,
        snippet_line_end=start + len(repo_lines) - 1,
        repo_lines=tuple(repo_lines),
    )
