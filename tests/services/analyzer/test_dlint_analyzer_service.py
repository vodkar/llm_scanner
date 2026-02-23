from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from clients.analyzers.dlint_scanner import DlintStaticAnalyzer
from models.base import StaticAnalyzerReport
from models.dlint_report import DlintIssue
from models.edges.analysis import StaticAnalysisReports
from models.nodes import CodeBlockNode
from models.nodes.finding import DlintFindingNode
from repositories.analyzers.base import IFindingsRepository
from repositories.graph import GraphRepository
from services.analyzer.dlint import DlintAnalyzerService


@pytest.fixture
def mock_graph_repository() -> MagicMock:
    return MagicMock(spec=GraphRepository)


@pytest.fixture
def mock_findings_repository() -> MagicMock:
    return MagicMock(spec=IFindingsRepository)


@pytest.fixture
def dlint_service(
    mock_graph_repository: MagicMock,
    mock_findings_repository: MagicMock,
    tmp_path: Path,
) -> DlintAnalyzerService:
    return DlintAnalyzerService(
        target=tmp_path,
        graph_repository=mock_graph_repository,
        findings_repository=mock_findings_repository,
    )


def test_finding_node_type_returns_dlint_finding_node(dlint_service: DlintAnalyzerService) -> None:
    assert dlint_service._finding_node_type == DlintFindingNode


def test_static_analyzer_is_dlint_scanner(
    dlint_service: DlintAnalyzerService, tmp_path: Path
) -> None:
    analyzer = dlint_service._static_analyzer
    assert isinstance(analyzer, DlintStaticAnalyzer)
    assert analyzer.src == tmp_path


def test_issue_payload_includes_issue_id(dlint_service: DlintAnalyzerService) -> None:
    issue = DlintIssue(
        code="DUO123",
        file=Path("src/app.py"),
        line_number=10,
        column_number=5,
        reason="Insecure use of eval",
    )

    payload = dlint_service._issue_payload(issue)

    assert payload["issue_id"] == 123
    assert payload["file"] == Path("src/app.py")
    assert payload["line_number"] == 10
    assert payload["reason"] == "Insecure use of eval"
    assert "code" not in payload
    assert "column_number" not in payload


def test_issue_payload_removes_code_and_column_number(dlint_service: DlintAnalyzerService) -> None:
    issue = DlintIssue(
        code="DUO105",
        file=Path("test.py"),
        line_number=1,
        column_number=0,
        reason="test",
    )

    payload = dlint_service._issue_payload(issue)

    assert "code" not in payload
    assert "column_number" not in payload


def test_normalize_issue_path_resolves_relative_to_target(
    dlint_service: DlintAnalyzerService,
    tmp_path: Path,
) -> None:
    relative_path = Path("src/app.py")
    normalized = dlint_service._normalize_issue_path(relative_path)
    assert normalized == Path("src/app.py")


def test_normalize_issue_path_handles_absolute_paths(
    dlint_service: DlintAnalyzerService,
    tmp_path: Path,
) -> None:
    absolute_path = tmp_path / "src" / "app.py"
    normalized = dlint_service._normalize_issue_path(absolute_path)
    assert normalized == Path("src/app.py")


@patch.object(DlintStaticAnalyzer, "run")
def test_enrich_graph_with_findings_creates_nodes_and_edges(
    mock_run: MagicMock,
    dlint_service: DlintAnalyzerService,
    mock_graph_repository: MagicMock,
    mock_findings_repository: MagicMock,
    tmp_path: Path,
) -> None:
    issue = DlintIssue(
        code="DUO107",
        file=tmp_path / "src/app.py",
        line_number=15,
        column_number=8,
        reason="Insecure random usage",
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

    dlint_service.enrich_graph_with_findings()

    mock_findings_repository.insert_nodes.assert_called_once()
    findings = mock_findings_repository.insert_nodes.call_args[0][0]
    assert len(findings) == 1
    assert isinstance(findings[0], DlintFindingNode)
    assert findings[0].file == Path("src/app.py")
    assert findings[0].line_number == 15
    assert findings[0].issue_id == 107

    mock_findings_repository.insert_edges.assert_called_once()
    edges = mock_findings_repository.insert_edges.call_args[0][0]
    assert len(edges) == 1
    assert isinstance(edges[0], StaticAnalysisReports)
    assert edges[0].src == str(findings[0].identifier)
    assert edges[0].dst == code_node.identifier


@patch.object(DlintStaticAnalyzer, "run")
def test_enrich_graph_with_findings_handles_no_code_node_match(
    mock_run: MagicMock,
    dlint_service: DlintAnalyzerService,
    mock_graph_repository: MagicMock,
    mock_findings_repository: MagicMock,
    tmp_path: Path,
) -> None:
    issue = DlintIssue(
        code="DUO108",
        file=tmp_path / "src/app.py",
        line_number=50,
        column_number=1,
        reason="Issue at unmapped line",
    )
    mock_run.return_value = StaticAnalyzerReport(issues=[issue])
    mock_graph_repository.get_nodes_by_file_and_line_numbers.return_value = {}

    dlint_service.enrich_graph_with_findings()

    mock_findings_repository.insert_nodes.assert_called_once()
    findings = mock_findings_repository.insert_nodes.call_args[0][0]
    assert len(findings) == 1

    mock_findings_repository.insert_edges.assert_called_once()
    edges = mock_findings_repository.insert_edges.call_args[0][0]
    assert len(edges) == 0


@patch.object(DlintStaticAnalyzer, "run")
def test_enrich_graph_with_findings_processes_multiple_issues(
    mock_run: MagicMock,
    dlint_service: DlintAnalyzerService,
    mock_graph_repository: MagicMock,
    mock_findings_repository: MagicMock,
    tmp_path: Path,
) -> None:
    issues = [
        DlintIssue(
            code="DUO101",
            file=tmp_path / "src/app.py",
            line_number=10,
            column_number=0,
            reason="Issue 1",
        ),
        DlintIssue(
            code="DUO102",
            file=tmp_path / "src/utils.py",
            line_number=20,
            column_number=0,
            reason="Issue 2",
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

    dlint_service.enrich_graph_with_findings()

    findings = mock_findings_repository.insert_nodes.call_args[0][0]
    assert len(findings) == 2
    assert findings[0].issue_id == 101
    assert findings[1].issue_id == 102

    edges = mock_findings_repository.insert_edges.call_args[0][0]
    assert len(edges) == 2
