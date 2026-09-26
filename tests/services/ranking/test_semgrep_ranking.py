"""Semgrep findings contribute to ranking evidence like Bandit findings do."""

from pathlib import Path

import pytest

from models.bandit_report import IssueSeverity
from models.nodes.finding import BanditFindingNode, FindingNode, SemgrepFindingNode
from services.ranking.ranking import (
    AGREEMENT_BOTH_ANALYZERS,
    AGREEMENT_MULTIPLE_FINDINGS,
    NodeRelevanceRankingService,
)


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _bandit(severity: IssueSeverity = IssueSeverity.HIGH, cwe_id: int = 78) -> BanditFindingNode:
    return BanditFindingNode(file=Path("a.py"), line_number=1, cwe_id=cwe_id, severity=severity)


def _semgrep(
    severity: IssueSeverity = IssueSeverity.HIGH, cwe_id: int | None = 78
) -> SemgrepFindingNode:
    return SemgrepFindingNode(file=Path("a.py"), line_number=1, cwe_id=cwe_id, severity=severity)


def _expected_evidence(
    service: NodeRelevanceRankingService, severity: IssueSeverity, agreement: float
) -> float:
    evidence = service.coefficients.finding_evidence_breakdown
    return service._clamp_score(
        evidence.severity * service._severity_score(severity)
        + evidence.confidence * service._severity_confidence(severity)
        + evidence.agreement * agreement
    )


@pytest.mark.parametrize("severity", list(IssueSeverity))
def test_semgrep_severity_scores_like_bandit(tmp_path: Path, severity: IssueSeverity) -> None:
    service = NodeRelevanceRankingService(project_root=tmp_path)

    assert service._finding_evidence_score([_semgrep(severity)]) == pytest.approx(
        service._finding_evidence_score([_bandit(severity)])
    )


def test_semgrep_and_bandit_count_as_analyzer_agreement(tmp_path: Path) -> None:
    service = NodeRelevanceRankingService(project_root=tmp_path)
    findings: list[FindingNode] = [_bandit(), _semgrep()]

    assert service._finding_evidence_score(findings) == pytest.approx(
        _expected_evidence(service, IssueSeverity.HIGH, AGREEMENT_BOTH_ANALYZERS)
    )


def test_two_semgrep_findings_are_not_analyzer_agreement(tmp_path: Path) -> None:
    service = NodeRelevanceRankingService(project_root=tmp_path)
    findings: list[FindingNode] = [_semgrep(), _semgrep()]

    assert service._finding_evidence_score(findings) == pytest.approx(
        _expected_evidence(service, IssueSeverity.HIGH, AGREEMENT_MULTIPLE_FINDINGS)
    )


def test_semgrep_high_risk_cwe_counts_as_path_evidence(tmp_path: Path) -> None:
    service = NodeRelevanceRankingService(project_root=tmp_path)

    assert service._security_path_score(
        snippet="", direct_findings=[_semgrep(cwe_id=78)]
    ) == pytest.approx(service._security_path_score(snippet="", direct_findings=[_bandit()]))
