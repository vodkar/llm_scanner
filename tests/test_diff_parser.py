"""Unit tests for diff_parser.parse_unified_diff."""

import sys
from pathlib import Path

# Ensure llm_scanner package dir is on the path for flat imports
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "llm_scanner"))

from diff_parser import _numbers_to_spans, parse_unified_diff  # noqa: E402
from models.context import FileSpans  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_SIMPLE_DIFF = """\
diff --git a/foo.py b/foo.py
index abc..def 100644
--- a/foo.py
+++ b/foo.py
@@ -1,4 +1,5 @@
 line1
+line2_added
 line3
-line4_removed
+line4_replacement
 line5
"""

_MULTI_FILE_DIFF = """\
diff --git a/foo.py b/foo.py
--- a/foo.py
+++ b/foo.py
@@ -10,3 +10,4 @@
 ctx
+added_10
 ctx2
 ctx3
diff --git a/bar.py b/bar.py
--- a/bar.py
+++ b/bar.py
@@ -5,2 +5,3 @@
 unchanged
+new_line
 another
"""

_DELETED_FILE_DIFF = """\
diff --git a/deleted.py b/deleted.py
--- a/deleted.py
+++ /dev/null
@@ -1,3 +0,0 @@
-removed1
-removed2
-removed3
"""

_REPO_ROOT = Path("/repo")


# ---------------------------------------------------------------------------
# _numbers_to_spans
# ---------------------------------------------------------------------------


class TestNumbersToSpans:
    def test_empty(self) -> None:
        assert _numbers_to_spans([]) == []

    def test_single(self) -> None:
        assert _numbers_to_spans([5]) == [(5, 5)]

    def test_consecutive(self) -> None:
        assert _numbers_to_spans([1, 2, 3]) == [(1, 3)]

    def test_non_consecutive(self) -> None:
        assert _numbers_to_spans([1, 3, 5]) == [(1, 1), (3, 3), (5, 5)]

    def test_mixed(self) -> None:
        assert _numbers_to_spans([1, 2, 4, 5, 7]) == [(1, 2), (4, 5), (7, 7)]


# ---------------------------------------------------------------------------
# parse_unified_diff
# ---------------------------------------------------------------------------


class TestParseUnifiedDiff:
    def test_simple_diff_added_lines(self) -> None:
        """Added lines appear at correct new-file line numbers."""
        result = parse_unified_diff(_SIMPLE_DIFF, _REPO_ROOT)
        assert len(result) == 1
        span: FileSpans = result[0]
        assert span.file_path == _REPO_ROOT / "foo.py"
        # hunk starts at new line 1; line1 is context(1), line2_added(2), line3 context(3),
        # line4_removal skips counter, line4_replacement is added(4)
        assert (2, 2) in span.line_spans
        assert (4, 4) in span.line_spans

    def test_multi_file_diff(self) -> None:
        result = parse_unified_diff(_MULTI_FILE_DIFF, _REPO_ROOT)
        assert len(result) == 2
        paths = {r.file_path for r in result}
        assert _REPO_ROOT / "foo.py" in paths
        assert _REPO_ROOT / "bar.py" in paths

    def test_deleted_file_ignored(self) -> None:
        """Files deleted ('+++ /dev/null') produce no FileSpans."""
        result = parse_unified_diff(_DELETED_FILE_DIFF, _REPO_ROOT)
        assert result == []

    def test_empty_diff(self) -> None:
        assert parse_unified_diff("", _REPO_ROOT) == []

    def test_multi_file_line_numbers(self) -> None:
        """Hunk start offset is respected for each file independently."""
        result = parse_unified_diff(_MULTI_FILE_DIFF, _REPO_ROOT)
        foo_spans = next(r for r in result if r.file_path == _REPO_ROOT / "foo.py")
        bar_spans = next(r for r in result if r.file_path == _REPO_ROOT / "bar.py")
        # foo hunk starts at new line 10; context(10), added(11)
        assert (11, 11) in foo_spans.line_spans
        # bar hunk starts at new line 5; context(5), added(6)
        assert (6, 6) in bar_spans.line_spans

    def test_consecutive_lines_merged(self) -> None:
        diff = """\
--- a/x.py
+++ b/x.py
@@ -1,1 +1,3 @@
+line1
+line2
+line3
"""
        result = parse_unified_diff(diff, _REPO_ROOT)
        assert len(result) == 1
        assert result[0].line_spans == [(1, 3)]
