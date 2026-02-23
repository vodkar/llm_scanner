from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from clients.analyzers.bandit import BanditStaticAnalyzer
from models.bandit_report import BanditIssue, IssueSeverity
from models.base import StaticAnalyzerReport
from models.edges.analysis import StaticAnalysisReports
from models.nodes import CodeBlockNode
from models.nodes.finding import BanditFindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.graph import GraphRepository
from services.analyzer.bandit import BanditAnalyzerService


@pytest.fixture
def mock_graph_repository() -> MagicMock:
    return MagicMock(spec=GraphRepository)


@pytest.fixture
def mock_findings_repository() -> MagicMock:
    return MagicMock(spec=IFindingsRepository)


@pytest.fixture
def bandit_service(
    mock_graph_repository: MagicMock,
    mock_findings_repository: MagicMock,
    tmp_path: Path,
) -> BanditAnalyzerService:
    return BanditAnalyzerService(
        target=tmp_path,
        graph_repository=mock_graph_repository,
        findings_repository=mock_findings_repository,
    )


def test_finding_node_type_returns_bandit_finding_node(
    bandit_service: BanditAnalyzerService,
) -> None:
    assert bandit_service._finding_node_type == BanditFindingNode


def test_static_analyzer_is_bandit_scanner(
    bandit_service: BanditAnalyzerService, tmp_path: Path
) -> None:
    analyzer = bandit_service._static_analyzer
    assert isinstance(analyzer, BanditStaticAnalyzer)
    assert analyzer.src == tmp_path


def test_issue_payload_renames_cwe_to_cwe_id(bandit_service: BanditAnalyzerService) -> None:
    issue = BanditIssue(
        cwe=79,
        file=Path("src/app.py"),
        line_number=10,
        column_number=5,
        line_range=[10, 12],
        severity=IssueSeverity.HIGH,
        reason="XSS vulnerability",
    )

    payload = bandit_service._issue_payload(issue)

    assert payload["cwe_id"] == 79
    assert "cwe" not in payload
    assert payload["file"] == Path("src/app.py")
    assert payload["line_number"] == 10
    assert payload["severity"] == IssueSeverity.HIGH
    assert payload["reason"] == "XSS vulnerability"


def test_issue_payload_removes_column_number_and_line_range(
    bandit_service: BanditAnalyzerService,
) -> None:
    issue = BanditIssue(
        cwe=22,
        file=Path("test.py"),
        line_number=1,
        column_number=0,
        line_range=[1, 5],
        severity=IssueSeverity.LOW,
        reason="test",
    )

    payload = bandit_service._issue_payload(issue)

    assert "column_number" not in payload
    assert "line_range" not in payload


def test_normalize_issue_path_resolves_relative_to_target(
    bandit_service: BanditAnalyzerService,
    tmp_path: Path,
) -> None:
    relative_path = Path("src/app.py")
    normalized = bandit_service._normalize_issue_path(relative_path)
    assert normalized == Path("src/app.py")


def test_normalize_issue_path_handles_absolute_paths(
    bandit_service: BanditAnalyzerService,
    tmp_path: Path,
) -> None:
    absolute_path = tmp_path / "src" / "app.py"
    normalized = bandit_service._normalize_issue_path(absolute_path)
    assert normalized == Path("src/app.py")


@patch.object(BanditStaticAnalyzer, "run")
def test_enrich_graph_with_findings_creates_nodes_and_edges(
    mock_run: MagicMock,
    bandit_service: BanditAnalyzerService,
    mock_graph_repository: MagicMock,
    mock_findings_repository: MagicMock,
    tmp_path: Path,
) -> None:
    issue = BanditIssue(
        cwe=89,
        file=tmp_path / "src/app.py",
        line_number=15,
        column_number=8,
        line_range=[15, 17],
        severity=IssueSeverity.MEDIUM,
        reason="SQL injection risk",
    )
    mock_run.return_value = StaticAnalyzerReport(issues=[issue])

    code_node = CodeBlockNode(
        identifier="codeblock:func@src/app.py:100",
        file_path=Path("src/app.py"),
        line_start=10,
        line_end=20,
    )
    mock_graph_repository.get_nodes_by_file_and_line_numbers.return_value = {
        Path("src/app.py"): {15: code_node}
    }

    bandit_service.enrich_graph_with_findings()

    mock_findings_repository.insert_nodes.assert_called_once()
    findings = mock_findings_repository.insert_nodes.call_args[0][0]
    assert len(findings) == 1
    assert isinstance(findings[0], BanditFindingNode)
    assert findings[0].file == Path("src/app.py")
    assert findings[0].line_number == 15
    assert findings[0].cwe_id == 89
    assert findings[0].severity == IssueSeverity.MEDIUM

    mock_findings_repository.insert_edges.assert_called_once()
    edges = mock_findings_repository.insert_edges.call_args[0][0]
    assert len(edges) == 1
    assert isinstance(edges[0], StaticAnalysisReports)
    assert edges[0].src == str(findings[0].identifier)
    assert edges[0].dst == code_node.identifier


@patch.object(BanditStaticAnalyzer, "run")
def test_enrich_graph_with_findings_handles_no_code_node_match(
    mock_run: MagicMock,
    bandit_service: BanditAnalyzerService,
    mock_graph_repository: MagicMock,
    mock_findings_repository: MagicMock,
    tmp_path: Path,
) -> None:
    issue = BanditIssue(
        cwe=798,
        file=tmp_path / "src/app.py",
        line_number=50,
        column_number=1,
        line_range=[50],
        severity=IssueSeverity.HIGH,
        reason="Hardcoded password",
    )
    mock_run.return_value = StaticAnalyzerReport(issues=[issue])
    mock_graph_repository.get_nodes_by_file_and_line_numbers.return_value = {}

    bandit_service.enrich_graph_with_findings()

    mock_findings_repository.insert_nodes.assert_called_once()
    findings = mock_findings_repository.insert_nodes.call_args[0][0]
    assert len(findings) == 1

    mock_findings_repository.insert_edges.assert_called_once()
    edges = mock_findings_repository.insert_edges.call_args[0][0]
    assert len(edges) == 0


@patch.object(BanditStaticAnalyzer, "run")
def test_enrich_graph_with_findings_processes_multiple_issues(
    mock_run: MagicMock,
    bandit_service: BanditAnalyzerService,
    mock_graph_repository: MagicMock,
    mock_findings_repository: MagicMock,
    tmp_path: Path,
) -> None:
    issues = [
        BanditIssue(
            cwe=79,
            file=tmp_path / "src/app.py",
            line_number=10,
            column_number=0,
            line_range=[10],
            severity=IssueSeverity.HIGH,
            reason="XSS vulnerability",
        ),
        BanditIssue(
            cwe=22,
            file=tmp_path / "src/utils.py",
            line_number=20,
            column_number=0,
            line_range=[20, 21],
            severity=IssueSeverity.LOW,
            reason="Path traversal",
        ),
    ]
    mock_run.return_value = StaticAnalyzerReport(issues=issues)

    code_node1 = CodeBlockNode(
        identifier="codeblock:func1@src/app.py:100",
        file_path=Path("src/app.py"),
        line_start=5,
        line_end=15,
    )
    code_node2 = CodeBlockNode(
        identifier="codeblock:func2@src/utils.py:200",
        file_path=Path("src/utils.py"),
        line_start=15,
        line_end=25,
    )
    mock_graph_repository.get_nodes_by_file_and_line_numbers.return_value = {
        Path("src/app.py"): {10: code_node1},
        Path("src/utils.py"): {20: code_node2},
    }

    bandit_service.enrich_graph_with_findings()

    findings = mock_findings_repository.insert_nodes.call_args[0][0]
    assert len(findings) == 2
    assert findings[0].cwe_id == 79
    assert findings[0].severity == IssueSeverity.HIGH
    assert findings[1].cwe_id == 22
    assert findings[1].severity == IssueSeverity.LOW

    edges = mock_findings_repository.insert_edges.call_args[0][0]
    assert len(edges) == 2


@patch.object(BanditStaticAnalyzer, "run")
def test_enrich_graph_with_findings_handles_mixed_node_matches(
    mock_run: MagicMock,
    bandit_service: BanditAnalyzerService,
    mock_graph_repository: MagicMock,
    mock_findings_repository: MagicMock,
    tmp_path: Path,
) -> None:
    issues = [
        BanditIssue(
            cwe=79,
            file=tmp_path / "src/app.py",
            line_number=10,
            column_number=0,
            line_range=[10],
            severity=IssueSeverity.HIGH,
            reason="Found match",
        ),
        BanditIssue(
            cwe=22,
            file=tmp_path / "src/app.py",
            line_number=99,
            column_number=0,
            line_range=[99],
            severity=IssueSeverity.LOW,
            reason="No match",
        ),
    ]
    mock_run.return_value = StaticAnalyzerReport(issues=issues)

    code_node = CodeBlockNode(
        identifier="codeblock:func@src/app.py:100",
        file_path=Path("src/app.py"),
        line_start=5,
        line_end=15,
    )
    mock_graph_repository.get_nodes_by_file_and_line_numbers.return_value = {
        Path("src/app.py"): {10: code_node}
    }

    bandit_service.enrich_graph_with_findings()

    findings = mock_findings_repository.insert_nodes.call_args[0][0]
    assert len(findings) == 2

    edges = mock_findings_repository.insert_edges.call_args[0][0]
    assert len(edges) == 1
    assert edges[0].src == str(findings[0].identifier)
