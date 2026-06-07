"""Predicates for identifying test code among context-assembler nodes.

Two complementary signals are provided:

* :func:`is_test_path` — a path/name heuristic for conventional test locations
  and ``test_*`` function names.
* :func:`text_uses_test_framework` — a content heuristic that inspects source
  text for pytest/unittest usage. The CPG does not store import statements, so
  this signal requires reading the file.

Both are pure functions; file access and memoization are the caller's concern.
"""

import re
from pathlib import Path
from typing import Final

_TEST_DIR_SEGMENTS: Final[frozenset[str]] = frozenset({"tests", "test"})
_TEST_DIR_SUFFIXES: Final[tuple[str, ...]] = ("_tests", "_test")
_TEST_FILENAMES: Final[frozenset[str]] = frozenset({"conftest.py"})
_TEST_FUNCTION_PREFIX: Final[str] = "test_"

_TEST_FRAMEWORK_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^\s*import\s+(?:pytest|unittest)\b", re.MULTILINE),
    re.compile(r"^\s*from\s+unittest\b", re.MULTILINE),
    re.compile(r"^\s*from\s+django\.test\b", re.MULTILINE),
    re.compile(r"^\s*from\s+pytest\b", re.MULTILINE),
    re.compile(r"@pytest\.(?:fixture|mark)\b"),
    re.compile(r"\bunittest\.TestCase\b"),
    re.compile(r"\(\s*TestCase\b"),
)


def is_test_path(file_path: Path | str, name: str | None = None) -> bool:
    """Return whether a node looks like test code by path or function name.

    Args:
        file_path: Repository-relative path of the node's source file.
        name: Optional node name (e.g. function name).

    Returns:
        ``True`` for conventional test locations/names, otherwise ``False``.
    """

    if name is not None and name.startswith(_TEST_FUNCTION_PREFIX):
        return True

    path = Path(file_path)
    if path.name in _TEST_FILENAMES:
        return True

    stem = path.name
    if stem.startswith(_TEST_FUNCTION_PREFIX) or stem.endswith("_test.py"):
        return True

    return any(
        segment in _TEST_DIR_SEGMENTS or segment.endswith(_TEST_DIR_SUFFIXES)
        for segment in path.parts
    )


def text_uses_test_framework(text: str) -> bool:
    """Return whether source text imports or uses a known test framework.

    Args:
        text: Full source text of a module.

    Returns:
        ``True`` when pytest/unittest (or ``django.test``) usage is detected.
    """

    return any(pattern.search(text) for pattern in _TEST_FRAMEWORK_PATTERNS)
