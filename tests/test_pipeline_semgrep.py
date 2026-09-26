"""Semgrep runs in the scanner pipeline only when enabled."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from clients.neo4j import Neo4jClient
from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.edges.analysis import StaticAnalysisReports
from models.nodes.finding import (
    BanditFindingNode,
    DlintFindingNode,
    FindingNode,
    SemgrepFindingNode,
)
from pipeline import GeneralScannerPipeline
from repositories.graph import GraphRepository
from services.analyzer.bandit import BanditAnalyzerService
from services.analyzer.dlint import DlintAnalyzerService
from services.analyzer.semgrep import SemgrepAnalyzerService
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from services.ranking.ranking import NodeRelevanceRankingService


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _pipeline(tmp_path: Path, **kwargs: object) -> GeneralScannerPipeline:
    return GeneralScannerPipeline(src=tmp_path, neo4j_client=MagicMock(spec=Neo4jClient), **kwargs)


def _service_types(pipeline: GeneralScannerPipeline, tmp_path: Path) -> list[type]:
    services = pipeline._analyzer_services(tmp_path, MagicMock(spec=GraphRepository))
    return [type(service) for service in services]


def test_semgrep_is_disabled_by_default(tmp_path: Path) -> None:
    assert _service_types(_pipeline(tmp_path), tmp_path) == [
        DlintAnalyzerService,
        BanditAnalyzerService,
    ]


def test_enable_semgrep_adds_configured_service(tmp_path: Path) -> None:
    pipeline = _pipeline(tmp_path, enable_semgrep=True, semgrep_config="p/django")

    services = pipeline._analyzer_services(tmp_path, MagicMock(spec=GraphRepository))

    assert [type(service) for service in services] == [
        DlintAnalyzerService,
        BanditAnalyzerService,
        SemgrepAnalyzerService,
    ]
    semgrep = services[-1]
    assert isinstance(semgrep, SemgrepAnalyzerService)
    assert semgrep.config == "p/django"


def test_build_cpg_feeds_semgrep_findings_into_ranking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dlint = DlintFindingNode(file=Path("a.py"), line_number=1, issue_id=102)
    bandit = BanditFindingNode(
        file=Path("a.py"), line_number=2, cwe_id=78, severity=IssueSeverity.HIGH
    )
    semgrep = _semgrep(IssueSeverity.HIGH)
    edge = StaticAnalysisReports(src=str(semgrep.identifier), dst=NodeID("function:f"))
    results: dict[type, tuple[list[FindingNode], list[StaticAnalysisReports]]] = {
        DlintAnalyzerService: ([dlint], []),
        BanditAnalyzerService: ([bandit], []),
        SemgrepAnalyzerService: ([semgrep], [edge]),
    }
    scored: list[tuple[list[FindingNode], list[StaticAnalysisReports]]] = []

    def _score(
        self: object,
        nodes: list[object],
        findings: list[FindingNode],
        edges: list[StaticAnalysisReports],
    ) -> list[object]:
        del self
        scored.append((findings, edges))
        return nodes

    for service_type, result in results.items():
        monkeypatch.setattr(
            service_type, "get_findings_with_edges", lambda self, nodes, r=result: r
        )
    monkeypatch.setattr(CPGDirectoryBuilder, "build", lambda self: ({}, []))
    monkeypatch.setattr(NodeRelevanceRankingService, "calculate_security_score", _score)
    monkeypatch.setattr(GraphRepository, "load", lambda self, nodes, edges: None)

    findings, edges = _pipeline(tmp_path, enable_semgrep=True).build_cpg()

    assert findings == [dlint, bandit, semgrep]
    assert edges == [edge]
    assert scored == [([dlint, bandit, semgrep], [edge])]


def _semgrep(severity: IssueSeverity) -> SemgrepFindingNode:
    return SemgrepFindingNode(
        file=Path("app.py"),
        line_number=7,
        rule_id="python.lang.security.audit.eval-detected",
        cwe_id=95,
        severity=severity,
    )


@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        (_semgrep(IssueSeverity.HIGH), True),
        (_semgrep(IssueSeverity.MEDIUM), False),
        (DlintFindingNode(file=Path("app.py"), line_number=1, issue_id=137), True),
    ],
)
def test_min_severity_filter_applies_to_semgrep(finding: FindingNode, expected: bool) -> None:
    assert GeneralScannerPipeline._meets_min_severity(finding, IssueSeverity.HIGH) is expected


def test_existing_review_messages_are_unchanged() -> None:
    bandit = BanditFindingNode(
        file=Path("app.py"), line_number=3, cwe_id=78, severity=IssueSeverity.HIGH
    )
    dlint = DlintFindingNode(file=Path("app.py"), line_number=1, issue_id=137)

    assert GeneralScannerPipeline._finding_message(bandit) == (
        "Bandit [CWE-78] severity=HIGH at app.py:3"
    )
    assert GeneralScannerPipeline._finding_message(dlint) == "Dlint [issue=137] at app.py:1"


def test_semgrep_review_message_names_rule_and_location() -> None:
    message = GeneralScannerPipeline._finding_message(_semgrep(IssueSeverity.HIGH))

    assert message == (
        "Semgrep [python.lang.security.audit.eval-detected] [CWE-95] severity=HIGH at app.py:7"
    )
