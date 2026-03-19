"""Unit tests for ContextRepository."""

from __future__ import annotations

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
            security_path_score=0.2,
        )
    ]
