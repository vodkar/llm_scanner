"""Integration tests for GraphRepository."""

from __future__ import annotations

from pathlib import Path

from clients.neo4j import Neo4jClient
from models.base import NodeID
from models.edges.call_graph import CallGraphCalls
from models.nodes import Node
from models.nodes.code import CodeBlockNode, FunctionNode
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


def test_get_nodes_by_file_and_line_numbers_returns_empty_for_empty_input(
    neo4j_client: Neo4jClient,
) -> None:
    """Verify lookup returns an empty mapping when no file lines are provided."""

    repo: GraphRepository = GraphRepository(neo4j_client)

    result: dict[Path, dict[int, Node]] = repo.get_nodes_by_file_and_line_numbers({})

    assert result == {}


def test_get_nodes_by_file_and_line_numbers_matches_existing_lines(
    neo4j_client: Neo4jClient,
) -> None:
    """Verify lookup resolves stored code nodes for requested file lines."""

    repo: GraphRepository = GraphRepository(neo4j_client)
    file_path: Path = Path("src/app.py")

    node_id_alpha: NodeID = NodeID.create("function", "alpha", file_path, 10)
    node_id_beta: NodeID = NodeID.create("function", "beta", file_path, 30)

    node_alpha: FunctionNode = FunctionNode(
        identifier=node_id_alpha,
        file_path=file_path,
        line_start=1,
        line_end=10,
        token_count=3,
        name="alpha",
    )
    node_beta: FunctionNode = FunctionNode(
        identifier=node_id_beta,
        file_path=file_path,
        line_start=20,
        line_end=40,
        token_count=4,
        name="beta",
    )

    repo.load({node_id_alpha: node_alpha, node_id_beta: node_beta}, [])

    result: dict[Path, dict[int, Node]] = repo.get_nodes_by_file_and_line_numbers(
        {file_path: [5, 25, 25, 100]}
    )

    assert file_path in result
    assert set(result[file_path].keys()) == {5, 25}
    assert isinstance(result[file_path][5], CodeBlockNode)
    assert isinstance(result[file_path][25], CodeBlockNode)
    assert result[file_path][5].identifier == node_id_alpha
    assert result[file_path][25].identifier == node_id_beta


def test_get_nodes_by_file_and_line_numbers_prefers_smallest_covering_span(
    neo4j_client: Neo4jClient,
) -> None:
    """Verify overlap resolution picks the node with the smallest line span."""

    repo: GraphRepository = GraphRepository(neo4j_client)
    file_path: Path = Path("src/app.py")

    wide_id: NodeID = NodeID.create("function", "wide", file_path, 10)
    narrow_id: NodeID = NodeID.create("function", "narrow", file_path, 20)

    wide_node: FunctionNode = FunctionNode(
        identifier=wide_id,
        file_path=file_path,
        line_start=1,
        line_end=100,
        token_count=20,
        name="wide",
    )
    narrow_node: FunctionNode = FunctionNode(
        identifier=narrow_id,
        file_path=file_path,
        line_start=45,
        line_end=55,
        token_count=5,
        name="narrow",
    )

    repo.load({wide_id: wide_node, narrow_id: narrow_node}, [])

    result: dict[Path, dict[int, Node]] = repo.get_nodes_by_file_and_line_numbers({file_path: [50]})

    assert file_path in result
    assert 50 in result[file_path]
    assert result[file_path][50].identifier == narrow_id
