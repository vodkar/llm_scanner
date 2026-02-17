"""Integration tests for DlintFindingsRepository."""

from __future__ import annotations

from pathlib import Path

from clients.neo4j import Neo4jClient
from models.base import NodeID
from models.edges.analysis import StaticAnalysisReports
from models.nodes.code import FunctionNode
from models.nodes.finding import DlintFindingNode
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.graph import GraphRepository
from tests.repositories.conftest import DLINT_FINDING_QUERY, REPORTS_EDGE_QUERY


def test_dlint_findings_repository_inserts_nodes_and_reports(
    neo4j_client: Neo4jClient,
) -> None:
    """Verify DlintFindingsRepository inserts findings and report edges."""

    graph_repo: GraphRepository = GraphRepository(neo4j_client)
    file_path: Path = Path("src/app.py")
    node_id: NodeID = NodeID.create("function", "delta", file_path, 30)
    node: FunctionNode = FunctionNode(
        identifier=node_id,
        file_path=file_path,
        line_start=20,
        line_end=40,
        token_count=5,
        name="delta",
    )
    graph_repo.load({node_id: node}, [])

    repo: DlintFindingsRepository = DlintFindingsRepository(client=neo4j_client)
    finding: DlintFindingNode = DlintFindingNode(
        file=file_path,
        line_number=25,
        issue_id=501,
    )

    repo.insert_nodes([finding])

    rows: list[dict[str, object]] = list(
        neo4j_client.run_read(DLINT_FINDING_QUERY, {"id": str(finding.identifier)})
    )
    assert len(rows) == 1
    assert rows[0]["file"] == "src/app.py"
    assert rows[0]["line_number"] == 25
    assert rows[0]["issue_id"] == 501

    reports_edge: StaticAnalysisReports = StaticAnalysisReports(
        src=str(finding.identifier),
        dst=node_id,
    )
    repo.insert_edges([reports_edge])

    edge_rows: list[dict[str, object]] = list(
        neo4j_client.run_read(
            REPORTS_EDGE_QUERY,
            {"finding_id": str(finding.identifier), "code_id": str(node_id)},
        )
    )
    assert len(edge_rows) == 1
    assert edge_rows[0]["rel_count"] == 1


def test_dlint_findings_repository_iterates_project_findings(
    neo4j_client: Neo4jClient,
) -> None:
    """Verify DlintFindingsRepository returns project-scoped findings."""

    repo: DlintFindingsRepository = DlintFindingsRepository(client=neo4j_client)
    project_root: Path = Path("src")
    project_file: Path = project_root / "utils.py"
    outside_file: Path = Path("vendor") / "utils.py"

    findings: list[DlintFindingNode] = [
        DlintFindingNode(
            file=project_file,
            line_number=12,
            issue_id=501,
        ),
        DlintFindingNode(
            file=outside_file,
            line_number=1,
            issue_id=401,
        ),
    ]

    repo.insert_nodes(findings)

    project_findings: list[DlintFindingNode] = repo.iter_findings_for_project(project_root)

    assert len(project_findings) == 1
    assert project_findings[0].file == project_file
    assert project_findings[0].issue_id == 501
