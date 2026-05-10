"""Unit tests for ContextRepository."""

from pathlib import Path
from unittest.mock import Mock

from clients.neo4j import Neo4jClient
from models.base import NodeID
from models.context import CodeContextNode
from repositories.context import ContextRepository


def test_context_repository_aggregates_duplicate_rows_with_shallowest_depth() -> None:
    """Duplicate traversal rows should increment repeats and keep the smallest depth."""

    client = Mock(spec=Neo4jClient)
    client.run_write.return_value = None
    client.run_read.side_effect = [
        [{"relationshipType": "CALLS"}],
        [
            {
                "id": "node-1",
                "depth": 2,
                "file_path": "src/app.py",
                "line_start": 1,
                "line_end": 5,
                "node_kind": "FunctionNode",
                "name": "alpha",
                "finding_evidence_score": 0.7,
                "security_path_score": 0.2,
            },
            {
                "id": "node-1",
                "depth": 0,
                "file_path": "src/app.py",
                "line_start": 1,
                "line_end": 5,
                "node_kind": "FunctionNode",
                "name": "alpha",
                "finding_evidence_score": 0.7,
                "security_path_score": 0.2,
            },
            {
                "id": "node-1",
                "depth": 1,
                "file_path": "src/app.py",
                "line_start": 1,
                "line_end": 5,
                "node_kind": "FunctionNode",
                "name": "alpha",
                "finding_evidence_score": 0.7,
                "security_path_score": 0.2,
            },
        ],
    ]

    repository = ContextRepository(client=client)

    rows = repository.fetch_code_neighborhood_batch(["node-1", "node-2"], 2)

    assert rows == [
        CodeContextNode(
            identifier=NodeID("node-1"),
            node_kind="FunctionNode",
            name="alpha",
            file_path=Path("src/app.py"),
            line_start=1,
            line_end=5,
            depth=0,
            repeats=2,
            finding_evidence_score=0.7,
            security_path_score=0.2,
        )
    ]


def test_context_repository_preserves_security_scores_from_span_lookup() -> None:
    """Span lookup should preserve both security score components."""

    client = Mock(spec=Neo4jClient)
    client.run_write.return_value = None
    client.run_read.side_effect = [
        [{"relationshipType": "CALLS"}],
        [
            {
                "id": "node-1",
                "file_path": "src/app.py",
                "node_file_path": "src/app.py",
                "line_start": 10,
                "line_end": 15,
                "node_kind": "FunctionNode",
                "name": "sink",
                "finding_evidence_score": 1.0,
                "security_path_score": 0.8,
            }
        ],
    ]

    repository = ContextRepository(client=client)

    rows = repository.fetch_code_nodes_by_file_spans(
        [{"file_path": "src/app.py", "start_line": 12, "end_line": 12}]
    )

    assert rows == [
        CodeContextNode(
            identifier=NodeID("node-1"),
            node_kind="FunctionNode",
            name="sink",
            file_path=Path("src/app.py"),
            line_start=10,
            line_end=15,
            depth=0,
            finding_evidence_score=1.0,
            security_path_score=0.8,
        )
    ]


def test_context_repository_merges_overlapping_spans_before_query() -> None:
    """Overlapping and adjacent spans should be coalesced before Neo4j lookup."""

    client = Mock(spec=Neo4jClient)
    client.run_write.return_value = None
    client.run_read.side_effect = [
        [{"relationshipType": "CALLS"}],
        [],
    ]

    repository = ContextRepository(client=client)

    repository.fetch_code_nodes_by_file_spans(
        [
            {"file_path": "src/app.py", "start_line": 10, "end_line": 12},
            {"file_path": "src/app.py", "start_line": 11, "end_line": 15},
            {"file_path": "src/app.py", "start_line": 16, "end_line": 18},
            {"file_path": "src/other.py", "start_line": 5, "end_line": 5},
        ]
    )

    _, params = client.run_read.call_args_list[1].args
    assert params == {
        "rows": [
            {"file_path": "src/app.py", "start_line": 10, "end_line": 18},
            {"file_path": "src/other.py", "start_line": 5, "end_line": 5},
        ]
    }


def test_fetch_with_edge_paths_merges_per_edge_type_depths() -> None:
    """Per-edge-type depths must be merged into ``edge_depths`` per node."""

    client = Mock(spec=Neo4jClient)
    client.run_write.return_value = None
    client.run_read.side_effect = [
        [{"relationshipType": "FLOWS_TO"}, {"relationshipType": "CONTAINS"}],
        [
            {
                "id": "node-1",
                "depth": 1,
                "file_path": "src/app.py",
                "line_start": 1,
                "line_end": 5,
                "node_kind": "FunctionNode",
                "name": "alpha",
                "finding_evidence_score": 0.0,
                "security_path_score": 0.0,
            },
        ],
        [
            {
                "id": "node-1",
                "depth": 3,
                "file_path": "src/app.py",
                "line_start": 1,
                "line_end": 5,
                "node_kind": "FunctionNode",
                "name": "alpha",
                "finding_evidence_score": 0.0,
                "security_path_score": 0.0,
            },
            {
                "id": "node-2",
                "depth": 2,
                "file_path": "src/app.py",
                "line_start": 10,
                "line_end": 15,
                "node_kind": "ClassNode",
                "name": "Helper",
                "finding_evidence_score": 0.0,
                "security_path_score": 0.0,
            },
        ],
    ]

    repository = ContextRepository(client=client)

    nodes = repository.fetch_code_neighborhood_with_edge_paths(["node-1"], 4)

    nodes_by_id = {node.identifier: node for node in nodes}
    assert nodes_by_id[NodeID("node-1")].depth == 1
    assert nodes_by_id[NodeID("node-1")].edge_depths == {"FLOWS_TO": 1, "CONTAINS": 3}
    assert nodes_by_id[NodeID("node-2")].depth == 2
    assert nodes_by_id[NodeID("node-2")].edge_depths == {"CONTAINS": 2}


def test_fetch_with_edge_paths_returns_empty_for_empty_start_ids() -> None:
    """No start IDs means no Neo4j read should happen and an empty list returns."""

    client = Mock(spec=Neo4jClient)
    client.run_write.return_value = None
    client.run_read.return_value = [{"relationshipType": "FLOWS_TO"}]

    repository = ContextRepository(client=client)

    assert repository.fetch_code_neighborhood_with_edge_paths([], 3) == []
