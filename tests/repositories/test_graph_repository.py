"""Integration tests for GraphRepository."""

from pathlib import Path

from clients.neo4j import Neo4jClient
from models.base import NodeID
from models.edges.call_graph import CallGraphCalls
from models.nodes.code import FunctionNode
from repositories.graph import GraphRepository
from tests.repositories.conftest import GRAPH_EDGE_QUERY, GRAPH_NODE_QUERY


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
    edges: list[CallGraphCalls] = [CallGraphCalls(src=node_id_a, dst=node_id_b)]

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
