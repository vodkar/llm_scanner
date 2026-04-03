from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clients.analyzers.dlint_scanner import DlintStaticAnalyzer
from models.dlint_report import DlintIssue
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
        project_root=tmp_path,
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
