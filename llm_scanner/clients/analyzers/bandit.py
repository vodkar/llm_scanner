import json
import subprocess
from pathlib import Path

from clients.analyzers.base import IStaticAnalyzer
from models.bandit_report import BanditIssue, IssueSeverity

from models.base import StaticAnalyzerReport


class BanditStaticAnalyzer(IStaticAnalyzer):
    src: Path

    def run(self) -> StaticAnalyzerReport[BanditIssue]:  # type: ignore
        report_path: Path = Path("bandit_report.json")
        subprocess.run(
            ["bandit", "-f", "json", "-o", str(report_path), "-r", str(self.src)]
        )
        json_report = report_path.read_text()
        report_data = json.loads(json_report)

        issues: list[BanditIssue] = []
        for report in report_data["results"]:
            file = Path(report["filename"])
            file.read_text()
            issues.append(
                BanditIssue(
                    cwe=report["issue_cwe"]["id"],
                    file=Path(report["filename"]),
                    severity=IssueSeverity(report["issue_severity"]),
                    reason=report["issue_text"],
                    line_number=report["line_number"],
                    column_number=report["column_number"],
                    line_range=report["line_range"],
                )
            )

        return StaticAnalyzerReport(issues=issues)
