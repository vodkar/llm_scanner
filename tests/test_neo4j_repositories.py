"""Integration tests for Neo4j repositories."""

from __future__ import annotations

from pathlib import Path
from typing import Final, LiteralString

from clients.neo4j import Neo4jClient
from models.bandit_report import IssueSeverity
from models.base import NodeID
from models.edges.analysis import StaticAnalysisReports
from models.edges.call_graph import CallGraphCalls
from models.nodes.code import FunctionNode
from models.nodes.finding import BanditFindingNode, DlintFindingNode
from repositories.analyzers.bandit import BanditFindingsRepository
from repositories.analyzers.dlint import DlintFindingsRepository
from repositories.graph import GraphRepository

BANDIT_FINDING_QUERY: Final[LiteralString] = (
    "MATCH (n:Finding:BanditFinding {id:$id}) "
    "RETURN n.file AS file, n.cwe_id AS cwe_id, n.severity AS severity"
)
DLINT_FINDING_QUERY: Final[LiteralString] = (
    "MATCH (n:Finding:DlintFinding {id:$id}) "
    "RETURN n.file AS file, n.line_number AS line_number, n.issue_id AS issue_id"
)
GRAPH_NODE_QUERY: Final[LiteralString] = (
    "MATCH (n:Code:Function {id:$id}) RETURN n.id AS id, n.name AS name"
)
GRAPH_EDGE_QUERY: Final[LiteralString] = (
    "MATCH (s:Code {id:$src})-[r:CALLS]->(d:Code {id:$dst}) "
    "RETURN r.type AS rel_type, r.is_direct AS is_direct, r.call_depth AS call_depth"
)
REPORTS_EDGE_QUERY: Final[LiteralString] = (
    "MATCH (f:Finding {id:$finding_id})-[r:REPORTS]->(c:Code {id:$code_id}) "
    "RETURN count(r) AS rel_count"
)


def test_graph_repository_load_inserts_nodes_and_edges(neo4j_client: Neo4jClient) -> None:
    """Verify GraphRepository loads nodes and edges into Neo4j."""

    repo: GraphRepository = GraphRepository(neo4j_client)
    file_path: Path = Path("src/app.py")

    node_id_a: NodeID = NodeID.create("function", "alpha", file_path, 10)
    node_id_b: NodeID = NodeID.create("function", "beta", file_path, 50)

    node_a: FunctionNode = FunctionNode(
        identifier=node_id_a,
        file_path=file_path,
        line_start=1,
        line_end=5,
        token_count=3,
        name="alpha",
    )
    node_b: FunctionNode = FunctionNode(
        identifier=node_id_b,
        file_path=file_path,
        line_start=10,
        line_end=15,
        token_count=2,
        name="beta",
    )

    nodes: dict[NodeID, FunctionNode] = {node_id_a: node_a, node_id_b: node_b}
    edges: list[CallGraphCalls] = [
        CallGraphCalls(src=node_id_a, dst=node_id_b, is_direct=True, call_depth=1)
    ]

    repo.load(nodes, edges)

    node_rows: list[dict[str, object]] = list(
        neo4j_client.run_read(GRAPH_NODE_QUERY, {"id": str(node_id_a)})
    )
    assert len(node_rows) == 1
    assert node_rows[0]["id"] == str(node_id_a)
    assert node_rows[0]["name"] == "alpha"

    edge_rows: list[dict[str, object]] = list(
        neo4j_client.run_read(GRAPH_EDGE_QUERY, {"src": str(node_id_a), "dst": str(node_id_b)})
    )
    assert len(edge_rows) == 1
    assert edge_rows[0]["rel_type"] == "CALLS"
    assert edge_rows[0]["is_direct"] is True
    assert edge_rows[0]["call_depth"] == 1


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
