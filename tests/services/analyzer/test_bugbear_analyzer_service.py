from pathlib import Path
from unittest.mock import MagicMock

from models.bandit_report import IssueSeverity
from models.bugbear_report import BugbearIssue
from models.nodes.finding import BugbearFindingNode
from models.static_finding import AnalyzerTool
from repositories.analyzers.base import IFindingsRepository
from repositories.graph import GraphRepository
from services.analyzer.bugbear import BugbearAnalyzerService
from services.benchmark.static_findings import _tool_for


def test_issue_payload_builds_medium_severity_finding(tmp_path: Path) -> None:
    service = BugbearAnalyzerService(
        project_root=tmp_path,
        graph_repository=MagicMock(spec=GraphRepository),
        findings_repository=MagicMock(spec=IFindingsRepository),
    )
    issue = BugbearIssue(
        code="B006",
        file=Path("app/audit.py"),
        line_number=11,
        column_number=56,
        reason="Do not use mutable data structures for argument defaults.",
    )

    finding = BugbearFindingNode(**service._issue_payload(issue))

    assert (finding.rule_id, finding.severity, finding.cwe_id) == (
        "B006",
        IssueSeverity.MEDIUM,
        None,
    )
    assert _tool_for(finding) is AnalyzerTool.BUGBEAR
