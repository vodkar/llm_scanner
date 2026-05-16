from pathlib import Path

from services.source_code import SourceCodeService

# ---------------------------------------------------------------------------
# _find_function_line_span
# ---------------------------------------------------------------------------


def test_find_function_line_span_exact_match(tmp_path: Path) -> None:
    """Exact function text should be found and return correct 1-based span."""
    source = "import os\n\ndef foo():\n    pass\n\ndef bar():\n    return 1\n"
    f = tmp_path / "src.py"
    f.write_text(source, encoding="utf-8")

    span = SourceCodeService.find_function_line_span(f, "def foo():\n    pass")

    assert span == (3, 4)


def test_find_function_line_span_trailing_whitespace_in_file(tmp_path: Path) -> None:
    """Trailing whitespace in the file should not prevent matching."""
    source = "def foo():   \n    pass   \n"
    f = tmp_path / "src.py"
    f.write_text(source, encoding="utf-8")

    span = SourceCodeService.find_function_line_span(f, "def foo():\n    pass")

    assert span == (1, 2)


def test_find_function_line_span_extra_blank_lines_in_file(tmp_path: Path) -> None:
    """Blank file lines between matched needle lines should be skipped."""
    source = "def foo():\n\n    pass\n"
    f = tmp_path / "src.py"
    f.write_text(source, encoding="utf-8")

    span = SourceCodeService.find_function_line_span(f, "def foo():\n    pass")

    assert span == (1, 3)


def test_find_function_line_span_whitespace_normalised(tmp_path: Path) -> None:
    """Lines with different spacing should match via whitespace-normalised tier."""
    # File has double spaces; dataset has single spaces
    source = "def  foo( ):\n    pass\n"
    f = tmp_path / "src.py"
    f.write_text(source, encoding="utf-8")

    span = SourceCodeService.find_function_line_span(f, "def foo( ):\n    pass")

    assert span is not None


def test_find_function_line_span_dedented_needle(tmp_path: Path) -> None:
    """Function stored at deeper indentation should match after dedent (Tier 3)."""
    # Simulate a method inside a class: 8-space indentation in file
    source = "class Foo:\n    def bar(self):\n        return 42\n"
    f = tmp_path / "src.py"
    f.write_text(source, encoding="utf-8")

    # Dataset stores the function with only 4-space indentation (dedented)
    needle = "    def bar(self):\n        return 42"

    span = SourceCodeService.find_function_line_span(f, needle)

    # Should find via Tier 1 (exact after rstrip) since indentation matches
    assert span is not None
    assert span[0] == 2


def test_find_function_line_span_returns_none_when_not_found(tmp_path: Path) -> None:
    """Returns None when function text cannot be located in the file."""
    f = tmp_path / "src.py"
    f.write_text("def completely_different():\n    pass\n", encoding="utf-8")

    span = SourceCodeService.find_function_line_span(f, "def foo():\n    bad()")

    assert span is None


def test_find_function_line_span_missing_file(tmp_path: Path) -> None:
    """Returns None for a file that does not exist."""
    span = SourceCodeService.find_function_line_span(
        tmp_path / "nonexistent.py", "def foo():\n    pass"
    )
    assert span is None
