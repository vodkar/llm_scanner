from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clients.analyzers.bandit import BanditStaticAnalyzer
from models.bandit_report import BanditIssue, IssueSeverity
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
        project_root=tmp_path,
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
