"""Parse git unified diff output into FileSpans for the scanner pipeline."""

import re
from pathlib import Path

from models.context import FileSpans

_PLUS_FILE_PREFIX: str = "+++ b/"
_HUNK_RE: re.Pattern[str] = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_unified_diff(diff_text: str, repo_root: Path) -> list[FileSpans]:
    """Parse a git unified diff into a list of FileSpans covering added lines.

    Only ``+`` (added / modified) lines are captured; deleted lines are ignored
    since we scan what exists in the current state of the code.

    Spans of consecutive added lines within a hunk are merged into contiguous
    ``(start, end)`` ranges before being returned.

    Args:
        diff_text: Raw output of ``git diff`` or similar (unified diff format).
        repo_root: Absolute path to the repository root; used to build absolute
            file paths within each ``FileSpans`` entry.

    Returns:
        One ``FileSpans`` per changed file; files with no added lines are omitted.
    """
    file_added_lines: dict[Path, list[int]] = {}
    current_file: Path | None = None
    current_new_line: int = 0

    for line in diff_text.splitlines():
        # File header: +++ b/<path>  (new file) or +++ /dev/null (deleted file)
        if line.startswith("+++ "):
            if line.startswith(_PLUS_FILE_PREFIX):
                rel_path = line[len(_PLUS_FILE_PREFIX) :].strip()
                current_file = repo_root / rel_path
                current_new_line = 0
            else:
                current_file = None  # deleted file — no added lines to capture
            continue

        # Hunk header: @@ -old_start,old_count +new_start,new_count @@
        hunk_match = _HUNK_RE.match(line)
        if hunk_match:
            current_new_line = int(hunk_match.group(1))
            continue

        if current_file is None:
            continue

        if line.startswith("+"):
            # Added line — record its new-file line number
            file_added_lines.setdefault(current_file, []).append(current_new_line)
            current_new_line += 1
        elif line.startswith("-"):
            # Deleted line — does not advance the new-file line counter
            pass
        else:
            # Context line
            current_new_line += 1

    return [
        FileSpans(file_path=file_path, line_spans=_numbers_to_spans(sorted(lines)))
        for file_path, lines in file_added_lines.items()
        if lines
    ]


def _numbers_to_spans(sorted_lines: list[int]) -> list[tuple[int, int]]:
    """Merge a sorted list of line numbers into contiguous (start, end) spans."""
    if not sorted_lines:
        return []
    spans: list[tuple[int, int]] = []
    start = end = sorted_lines[0]
    for ln in sorted_lines[1:]:
        if ln == end + 1:
            end = ln
        else:
            spans.append((start, end))
            start = end = ln
    spans.append((start, end))
    return spans
