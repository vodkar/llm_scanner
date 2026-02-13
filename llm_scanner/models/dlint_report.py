from pathlib import Path

from models.base import StaticAnalyzerIssue


class DlintIssue(StaticAnalyzerIssue):
    code: str
    file: Path
    column_number: int

    @property
    def id(self) -> int:
        return int(self.code.strip("DUO"))
