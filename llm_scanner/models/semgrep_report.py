from models.bandit_report import IssueSeverity
from models.base import StaticAnalyzerIssue


class SemgrepIssue(StaticAnalyzerIssue):
    """One Semgrep result: rule id, severity, CWE and 0-based start column."""

    check_id: str
    severity: IssueSeverity
    cwe: int | None = None
    column_number: int = 0
    line_end: int | None = None
