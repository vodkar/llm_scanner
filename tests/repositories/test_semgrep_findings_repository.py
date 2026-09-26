"""Integration tests for SemgrepFindingsRepository."""

from pathlib import Path

from clients.neo4j import Neo4jClient
from models.bandit_report import IssueSeverity
from models.nodes.finding import SemgrepFindingNode
from repositories.analyzers.semgrep import SemgrepFindingsRepository
from tests.repositories.conftest import SEMGREP_FINDING_QUERY


def test_semgrep_findings_repository_inserts_nodes(neo4j_client: Neo4jClient) -> None:
    repo = SemgrepFindingsRepository(client=neo4j_client)
    finding = SemgrepFindingNode(
        file=Path("src/app.py"),
        line_number=12,
        rule_id="python.lang.security.audit.eval-detected",
        cwe_id=None,
        severity=IssueSeverity.LOW,
    )

    repo.insert_nodes([finding])

    rows: list[dict[str, object]] = list(
        neo4j_client.run_read(SEMGREP_FINDING_QUERY, {"id": str(finding.identifier)})
    )
    assert rows == [
        {
            "file": "src/app.py",
            "line_number": 12,
            "rule_id": "python.lang.security.audit.eval-detected",
            "cwe_id": None,
            "severity": "LOW",
        }
    ]
