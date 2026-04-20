"""Unit tests for ContextRepository."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

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

    rows = repository.fetch_code_nodes_by_file_lines(
        [{"file_path": "src/app.py", "line_number": 12}]
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


def test_fetch_finding_proximity_scores_aggregates_per_node() -> None:
    """Per-node proximity = max(hop_decay(hop) x evidence) across anchors, clamped to 1.0."""

    client = Mock(spec=Neo4jClient)
    client.run_write.return_value = None
    client.run_read.side_effect = [
        [{"relationshipType": "CALLS"}],
        [
            {
                "node_id": "n1",
                "anchor_distances": [
                    {"hop": 0, "evidence": 1.0},
                    {"hop": 2, "evidence": 0.4},
                ],
            },
            {
                "node_id": "n2",
                "anchor_distances": [{"hop": 3, "evidence": 0.9}],
            },
        ],
    ]

    repository = ContextRepository(client=client)

    scores = repository.fetch_finding_proximity_scores(
        anchor_evidence={NodeID("a1"): 1.0, NodeID("a2"): 0.4},
        max_depth=4,
    )

    # n1: max(1.00*1.0, 0.70*0.4) = 1.00
    # n2: 0.55*0.9 = 0.495
    assert scores[NodeID("n1")] == pytest.approx(1.00)
    assert scores[NodeID("n2")] == pytest.approx(0.495, rel=1e-3)


def test_fetch_finding_proximity_scores_empty_anchors_skips_query() -> None:
    """No anchors => empty dict, no read invocation beyond repository init."""

    client = Mock(spec=Neo4jClient)
    client.run_write.return_value = None
    client.run_read.return_value = [{"relationshipType": "CALLS"}]

    repository = ContextRepository(client=client)

    scores = repository.fetch_finding_proximity_scores(anchor_evidence={}, max_depth=4)

    assert scores == {}
    # only the relationship-types query (run during model_post_init) was issued
    assert client.run_read.call_count == 1
