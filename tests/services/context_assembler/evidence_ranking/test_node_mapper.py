"""Tests for the node mapper that converts candidates back into context nodes."""

from pathlib import Path

import pytest

from models.context import CodeContextNode
from models.context_ranking import EvidenceRole, RankingCandidate
from services.context_assembler.evidence_ranking.node_mapper import NodeMapper


@pytest.fixture(autouse=True)
def clear_neo4j_database() -> None:
    """Override the global Neo4j autouse fixture for pure unit tests."""

    return None


def _candidate(
    *,
    identifier: str,
    roles: frozenset[EvidenceRole] = frozenset({EvidenceRole.SINK}),
    file_path: str = "a.py",
    line_start: int = 1,
) -> RankingCandidate:
    return RankingCandidate(
        source_node=CodeContextNode(
            identifier=identifier,  # type: ignore[arg-type]
            file_path=Path(file_path),
            line_start=line_start,
            line_end=line_start + 5,
            depth=0 if EvidenceRole.ROOT in roles else 1,
        ),
        roles=roles,
        estimated_token_count=10,
        clipped_line_start=line_start,
        clipped_line_end=line_start + 5,
    )


def test_root_candidates_appear_first() -> None:
    """ROOT-tagged candidates must precede non-root selected candidates."""

    sink = _candidate(identifier="sink", roles=frozenset({EvidenceRole.SINK}))
    root = _candidate(identifier="root", roles=frozenset({EvidenceRole.ROOT}))

    nodes = NodeMapper().map_to_nodes(selected=[sink, root], rejected=[])

    assert [n.identifier for n in nodes] == ["root", "sink"]


def test_selected_precede_rejected() -> None:
    """All selected nodes appear before any rejected node, regardless of relevance."""

    selected = _candidate(identifier="kept")
    rejected = _candidate(identifier="dropped")

    nodes = NodeMapper().map_to_nodes(selected=[selected], rejected=[rejected])

    assert [n.identifier for n in nodes] == ["kept", "dropped"]


def test_rejected_preserve_input_order() -> None:
    """Rejected candidates preserve their input order so the renderer's break is deterministic."""

    a = _candidate(identifier="a", line_start=1)
    b = _candidate(identifier="b", line_start=10)
    c = _candidate(identifier="c", line_start=20)

    nodes = NodeMapper().map_to_nodes(selected=[], rejected=[c, a, b])

    assert [n.identifier for n in nodes] == ["c", "a", "b"]


def test_deduplicates_by_identifier() -> None:
    """When the same node appears in selected and rejected, only one copy is emitted."""

    cand = _candidate(identifier="dup")

    nodes = NodeMapper().map_to_nodes(selected=[cand], rejected=[cand])

    assert [n.identifier for n in nodes] == ["dup"]


def test_returns_source_nodes_not_candidates() -> None:
    """The mapper must return ``CodeContextNode`` instances, not ``RankingCandidate``."""

    cand = _candidate(identifier="x")

    [node] = NodeMapper().map_to_nodes(selected=[cand], rejected=[])

    assert isinstance(node, CodeContextNode)
    assert node is cand.source_node


def test_empty_inputs_return_empty_list() -> None:
    assert NodeMapper().map_to_nodes(selected=[], rejected=[]) == []
