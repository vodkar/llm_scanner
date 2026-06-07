"""Guards for the decoupling of ingest vs neighborhood-traversal edge sets."""

from repositories.queries import (
    RELATIONSHIP_QUERY_BY_TYPE,
    code_traversal_relationship_types,
    path_fill_relationship_types,
)


def test_contains_is_ingestable() -> None:
    """CONTAINS edges must have an ingest query so they get written to Neo4j."""
    assert "CONTAINS" in RELATIONSHIP_QUERY_BY_TYPE


def test_contains_excluded_from_neighborhood_traversal() -> None:
    """Neighborhood BFS must not expand through structural CONTAINS edges."""
    assert "CONTAINS" not in code_traversal_relationship_types()


def test_neighborhood_traversal_keeps_dataflow_and_callgraph() -> None:
    """The taint/call chain edge types must remain in the traversal set."""
    traversal = set(code_traversal_relationship_types())
    assert {"FLOWS_TO", "DEFINED_BY", "USED_BY", "CALLS", "CALLED_BY"} <= traversal


def test_contains_used_for_path_fill() -> None:
    """Path-fill should keep a fetched class node connected to its member."""
    assert "CONTAINS" in path_fill_relationship_types()
