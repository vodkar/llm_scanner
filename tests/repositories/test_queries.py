"""Unit tests for query builder helpers in repositories.queries."""

from __future__ import annotations

from repositories.queries import (
    FINDING_PROXIMITY_HOP_DECAY,
    finding_proximity_query,
    finding_proximity_score_from_hop,
)


def test_finding_proximity_score_from_hop_uses_table() -> None:
    """Scores for hops present in the decay table should match the table."""

    assert finding_proximity_score_from_hop(0) == FINDING_PROXIMITY_HOP_DECAY[0]
    assert finding_proximity_score_from_hop(1) == FINDING_PROXIMITY_HOP_DECAY[1]


def test_finding_proximity_score_from_hop_falls_back_for_far_hops() -> None:
    """Hops beyond the table should fall back to the default below the last step."""

    assert 0.0 < finding_proximity_score_from_hop(99) < FINDING_PROXIMITY_HOP_DECAY[4]


def test_finding_proximity_query_uses_unwind_and_collects_per_node() -> None:
    """Positive-depth query should fan out per-anchor with UNWIND and collect hops."""

    query = finding_proximity_query(max_depth=3, relationship_types=("FLOWS_TO", "CALLS"))

    assert "UNWIND $anchors AS anchor" in query
    assert "[:FLOWS_TO|CALLS*0..3]" in query
    assert "collect(" in query
    assert "min(length(p))" in query


def test_finding_proximity_query_depth_zero_returns_anchors_only() -> None:
    """Zero-depth or empty-relationship query should short-circuit to anchor rows."""

    query = finding_proximity_query(max_depth=0, relationship_types=("FLOWS_TO",))

    assert "UNWIND $anchors AS anchor" in query
    assert "collect({hop: 0" in query
