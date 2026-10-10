from pathlib import Path

from models.base import StaticAnalyzerIssue


class BugbearIssue(StaticAnalyzerIssue):
    """A flake8-bugbear report, e.g. ``B006`` (mutable default argument)."""

    code: str
    file: Path
    column_number: int
