"""Integration tests for BanditFindingsRepository."""

from __future__ import annotations

from pathlib import Path

from clients.neo4j import Neo4jClient
from models.bandit_report import IssueSeverity
from models.nodes.finding import BanditFindingNode
from repositories.analyzers.bandit import BanditFindingsRepository
from tests.repositories.conftest import BANDIT_FINDING_QUERY


def test_bandit_findings_repository_inserts_nodes(neo4j_client: Neo4jClient) -> None:
    """Verify BanditFindingsRepository inserts findings nodes."""

    repo: BanditFindingsRepository = BanditFindingsRepository(client=neo4j_client)
    finding: BanditFindingNode = BanditFindingNode(
        file=Path("src/app.py"),
        line_number=12,
        cwe_id=79,
        severity=IssueSeverity.HIGH,
    )

    repo.insert_nodes([finding])

    rows: list[dict[str, object]] = list(
        neo4j_client.run_read(BANDIT_FINDING_QUERY, {"id": str(finding.identifier)})
    )
    assert len(rows) == 1
    assert rows[0]["file"] == "src/app.py"
    assert rows[0]["cwe_id"] == 79
    assert rows[0]["severity"] == IssueSeverity.HIGH.value


def test_bandit_findings_repository_iterates_project_findings(
    neo4j_client: Neo4jClient,
) -> None:
    """Verify BanditFindingsRepository returns project-scoped findings."""

    repo: BanditFindingsRepository = BanditFindingsRepository(client=neo4j_client)
    project_root: Path = Path("src")
    project_file: Path = project_root / "app.py"
    outside_file: Path = Path("external") / "app.py"

    findings: list[BanditFindingNode] = [
        BanditFindingNode(
            file=project_file,
            line_number=10,
            cwe_id=79,
            severity=IssueSeverity.HIGH,
        ),
        BanditFindingNode(
            file=outside_file,
            line_number=5,
            cwe_id=22,
            severity=IssueSeverity.LOW,
        ),
    ]

    repo.insert_nodes(findings)

    project_findings: list[BanditFindingNode] = repo.iter_findings_for_project(project_root)

    assert len(project_findings) == 1
    assert project_findings[0].file == project_file
    assert project_findings[0].cwe_id == 79
    assert project_findings[0].severity == IssueSeverity.HIGH
