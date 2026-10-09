"""Tests for narrowing diff-mode root locations to changed lines."""

from pathlib import Path

import pytest

from models.context import FileSpans, RootContext
from pipeline import _changed_lines

_ROOT = RootContext(file_path=Path("app/main.py"), line_start=22, line_end=28, code="")


@pytest.mark.parametrize(
    ("changed_spans", "expected"),
    [
        ([FileSpans(Path("app/main.py"), [(24, 27)])], (24, 27)),
        ([FileSpans(Path("app/main.py"), [(1, 5), (25, 25), (27, 40)])], (25, 28)),
        ([FileSpans(Path("app/other.py"), [(24, 27)])], (22, 28)),
        ([FileSpans(Path("app/main.py"), [(30, 35)])], (22, 28)),
        ([], (22, 28)),
    ],
)
def test_changed_lines_narrows_root_to_changed_overlap(
    changed_spans: list[FileSpans], expected: tuple[int, int]
) -> None:
    assert _changed_lines(_ROOT, changed_spans) == expected
