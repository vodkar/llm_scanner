from __future__ import annotations

import re
import subprocess
from pathlib import Path

from clients.analyzers.base import IStaticAnalyzer
from models.base import StaticAnalyzerReport
from models.dlint_report import DlintIssue


class DlintStaticAnalyzer(IStaticAnalyzer):
    """Run Dlint (via flake8) and parse results.

    This invokes `python -m flake8 --select=DUO` against the provided source
    directory. Output is parsed in the default format of flake8 which is
    `<path>:<line>:<col>: <code> <message>` for each finding.
    """

    src: Path

    def run(self) -> StaticAnalyzerReport[DlintIssue]:  # type: ignore
        report_path: Path = Path("dlint_report.txt")

        # Run flake8 with Dlint rules only; We don't fail on non-zero exit as
        # flake8 returns non-zero when issues are found.
        result = subprocess.run(
            [
                "python",
                "-m",
                "flake8",
                "--select=DUO",
                str(self.src),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        report_path.write_text(result.stdout)

        issues: list[DlintIssue] = []
        pattern = re.compile(r"^(.*?):(\d+):(\d+):\s+([A-Z]+\d+)\s+(.*)$")
        for line in result.stdout.splitlines():
            match = pattern.match(line.strip())
            if not match:
                # Skip unparsable lines (e.g., empty or configuration notes)
                continue
            path_str, line_str, col_str, code, message = match.groups()
            file_path: Path = Path(path_str)
            line_no: int = int(line_str)
            col_no: int = int(col_str)
            issues.append(
                DlintIssue(
                    code=code,
                    file=file_path,
                    reason=message.strip(),
                    line_number=line_no,
                    column_number=col_no,
                )
            )

        return StaticAnalyzerReport(issues=issues)
