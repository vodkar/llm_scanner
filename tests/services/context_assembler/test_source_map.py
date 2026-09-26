"""Tests for snippet ↔ repo source-map helpers."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from models.context import SnippetSegment
from services.context_assembler.source_map import (
    RenderedLine,
    build_source_map,
    resolve_snippet_line,
)


def test_build_groups_consecutive_lines_per_file() -> None:
    rendered: list[RenderedLine] = [
        (Path("a.py"), 1, "def a():"),
        (Path("a.py"), 3, "    return 1"),
        (Path("b.py"), 10, "def b():"),
    ]

    segments = build_source_map(rendered)

    assert segments == [
        SnippetSegment(
            file_path=Path("a.py"), snippet_line_start=1, snippet_line_end=2, repo_lines=(1, 3)
        ),
        SnippetSegment(
            file_path=Path("b.py"), snippet_line_start=3, snippet_line_end=3, repo_lines=(10,)
        ),
    ]


def test_build_empty_input_gives_empty_map() -> None:
    assert build_source_map([]) == []


def test_resolve_hit_and_miss() -> None:
    segments = build_source_map(
        [(Path("a.py"), 1, "x"), (Path("a.py"), 3, "y"), (Path("a.py"), 4, "z")]
    )

    assert resolve_snippet_line(segments, Path("a.py"), 3) == 2
    assert resolve_snippet_line(segments, Path("a.py"), 2) is None
    assert resolve_snippet_line(segments, Path("c.py"), 1) is None


def test_resolve_distinguishes_files() -> None:
    segments = build_source_map([(Path("a.py"), 5, "x"), (Path("b.py"), 5, "y")])

    assert resolve_snippet_line(segments, Path("a.py"), 5) == 1
    assert resolve_snippet_line(segments, Path("b.py"), 5) == 2


def test_segment_rejects_length_mismatch() -> None:
    with pytest.raises(ValidationError):
        SnippetSegment(
            file_path=Path("a.py"), snippet_line_start=1, snippet_line_end=3, repo_lines=(1,)
        )


def test_segment_rejects_zero_start() -> None:
    with pytest.raises(ValidationError):
        SnippetSegment(
            file_path=Path("a.py"), snippet_line_start=0, snippet_line_end=0, repo_lines=(1,)
        )
