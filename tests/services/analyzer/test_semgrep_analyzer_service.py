from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clients.analyzers.semgrep import SemgrepStaticAnalyzer
from models.bandit_report import IssueSeverity
from models.semgrep_report import SemgrepIssue
from repositories.analyzers.base import IFindingsRepository
from repositories.graph import GraphRepository
from services.analyzer.semgrep import SemgrepAnalyzerService


@pytest.fixture
def semgrep_service(tmp_path: Path) -> SemgrepAnalyzerService:
    return SemgrepAnalyzerService(
        project_root=tmp_path,
        graph_repository=MagicMock(spec=GraphRepository),
        findings_repository=MagicMock(spec=IFindingsRepository),
        config="p/django",
    )


def test_static_analyzer_uses_configured_rules(
    semgrep_service: SemgrepAnalyzerService, tmp_path: Path
) -> None:
    analyzer = semgrep_service._static_analyzer

    assert isinstance(analyzer, SemgrepStaticAnalyzer)
    assert analyzer.src == tmp_path
    assert analyzer.config == "p/django"


def test_findings_are_semgrep_nodes_with_rule_and_cwe(
    semgrep_service: SemgrepAnalyzerService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issue = SemgrepIssue(
        check_id="python.lang.security.audit.eval-detected",
        file=tmp_path / "src" / "app.py",
        line_number=4,
        line_end=6,
        column_number=8,
        severity=IssueSeverity.MEDIUM,
        cwe=95,
        reason="eval detected",
    )
    monkeypatch.setattr(SemgrepStaticAnalyzer, "run", lambda self: MagicMock(issues=[issue]))

    findings, edges = semgrep_service.get_findings_with_edges([])

    assert edges == []
    finding = findings[0]
    assert type(finding).__name__ == "SemgrepFindingNode"
    assert finding.file == Path("src/app.py")
    assert finding.rule_id == "python.lang.security.audit.eval-detected"
    assert finding.cwe_id == 95
    assert finding.severity == IssueSeverity.MEDIUM
    assert finding.line_end == 6
    assert finding.column_number == 8
    assert finding.reason == "eval detected"
