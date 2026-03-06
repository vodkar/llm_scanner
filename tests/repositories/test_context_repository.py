"""Unit tests for ContextRepository."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

from clients.neo4j import Neo4jClient
from models.base import NodeID
from models.context import CodeContextNode
from repositories.context import ContextRepository


def test_context_repository_caches_neighborhood_reads() -> None:
    """Verify repeated neighborhood lookups reuse cached repository rows."""

    client = Mock(spec=Neo4jClient)
    client.run_write.return_value = None
    client.run_read.side_effect = [
        [{"relationshipType": "CALLS"}],
        [
            {
                "id": "node-1",
                "depth": 0,
                "file_path": "src/app.py",
                "line_start": 1,
                "line_end": 5,
                "node_kind": "FunctionNode",
                "name": "alpha",
            }
        ],
    ]

    repository = ContextRepository(client=client)

    first_rows = repository.fetch_code_neighborhood_batch(["node-1", "node-1"], 2)
    second_rows = repository.fetch_code_neighborhood_batch(["node-1"], 2)

    assert first_rows == second_rows
    assert first_rows == [
        CodeContextNode(
            node_id=NodeID("node-1"),
            node_kind="FunctionNode",
            name="alpha",
            file_path=Path("src/app.py"),
            line_start=1,
            line_end=5,
            depth=0,
        )
    ]
    assert client.run_read.call_count == 2
