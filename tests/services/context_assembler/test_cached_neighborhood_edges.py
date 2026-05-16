"""Regression guard: cached vs Neo4j-backed path-fill must produce identical context.

The tuner cache flow short-circuits ``_build_path_fill_adjacency`` to read
edges from ``cached_neighborhood_edges`` instead of Neo4j. The whole
optimisation rests on Phase 2 producing byte-identical output to the
non-cached path for the same inputs.
"""

from pathlib import Path
from typing import Any

from models.base import NodeID
from models.context import CodeContextNode
from repositories.context import ContextRepository
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import ContextNodeRankingStrategy


class _StubRepo(ContextRepository):
    """In-memory repository that returns canned edges."""

    edges: list[tuple[NodeID, NodeID, str]]

    def model_post_init(self, __context: Any) -> None:
        del __context

    def fetch_neighborhood_edges(
        self,
        node_ids: list[str],
        edge_types: tuple[str, ...] | None = None,
    ) -> list[tuple[NodeID, NodeID, str]]:
        del node_ids, edge_types
        return list(self.edges)


class _ScoreSortStrategy(ContextNodeRankingStrategy):
    """Sort by anchor first, then by descending score."""

    def rank_nodes(self, nodes: list[CodeContextNode]) -> list[CodeContextNode]:
        return sorted(
            nodes,
            key=lambda item: (item.depth != 0, -item.score, item.depth),
        )


def _make_node(
    name: str,
    *,
    line_start: int,
    line_end: int,
    depth: int,
    score: float,
) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"function:{name}"),
        node_kind="FunctionNode",
        name=name,
        file_path=Path("app.py"),
        line_start=line_start,
        line_end=line_end,
        depth=depth,
        score=score,
    )


def test_cached_path_matches_neo4j_path(tmp_path: Path) -> None:
    """assemble_from_nodes must return identical output for cached vs Neo4j path."""

    (tmp_path / "app.py").write_text(
        "def root_anchor():\n"
        "    return middle_helper()\n"
        "def middle_helper():\n"
        "    return sink_call()\n"
        "def sink_call():\n"
        "    return 1\n",
        encoding="utf-8",
    )

    root = _make_node("root_anchor", line_start=1, line_end=2, depth=0, score=1.0)
    middle = _make_node("middle_helper", line_start=3, line_end=4, depth=1, score=0.10)
    sink = _make_node("sink_call", line_start=5, line_end=6, depth=2, score=0.90)
    nodes = [root, middle, sink]
    edges: list[tuple[NodeID, NodeID, str]] = [
        (root.identifier, middle.identifier, "CALLS"),
        (middle.identifier, sink.identifier, "CALLS"),
    ]

    repo = _StubRepo.model_construct(
        client=None,
        traversal_relationship_types=(),
        path_fill_edge_types=("CALLS",),
        edges=edges,
    )
    via_neo4j = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=repo,
        max_call_depth=4,
        token_budget=1_000,
        ranking_strategy=_ScoreSortStrategy(),
    )

    via_cache = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=None,
        cached_neighborhood_edges=edges,
        max_call_depth=4,
        token_budget=1_000,
        ranking_strategy=_ScoreSortStrategy(),
    )

    context_via_neo4j = via_neo4j.assemble_from_nodes(tmp_path, nodes)
    context_via_cache = via_cache.assemble_from_nodes(tmp_path, nodes)

    assert context_via_neo4j.context_text == context_via_cache.context_text
    assert context_via_neo4j.token_count == context_via_cache.token_count


def test_missing_both_repo_and_cache_raises(tmp_path: Path) -> None:
    """Constructing the service with neither source must fail at adjacency time."""

    (tmp_path / "app.py").write_text("def f():\n    pass\ndef g():\n    pass\n", encoding="utf-8")
    root = _make_node("f", line_start=1, line_end=2, depth=0, score=1.0)
    middle = _make_node("g", line_start=3, line_end=4, depth=1, score=0.5)

    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=None,
        max_call_depth=4,
        token_budget=1_000,
        ranking_strategy=_ScoreSortStrategy(),
    )

    try:
        service.assemble_from_nodes(tmp_path, [root, middle])
    except RuntimeError as error:
        assert "cached_neighborhood_edges" in str(error)
    else:
        msg = "Expected RuntimeError when both Neo4j repo and cache are missing"
        raise AssertionError(msg)
