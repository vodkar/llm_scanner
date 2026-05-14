"""Unit tests for path-fill connectivity in ContextAssemblerService."""

from pathlib import Path
from typing import Any

from models.base import NodeID
from models.context import CodeContextNode, FileSpans
from repositories.context import ContextRepository
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import ContextNodeRankingStrategy


class _StubRepo(ContextRepository):
    """In-memory repository that returns canned nodes and edges."""

    nodes: list[CodeContextNode]
    edges: list[tuple[NodeID, NodeID, str]]

    def model_post_init(self, __context: Any) -> None:
        del __context

    def fetch_code_nodes_by_file_spans(
        self,
        rows: list[dict[str, object]],
    ) -> list[CodeContextNode]:
        del rows
        return [node for node in self.nodes if node.depth == 0]

    def fetch_code_neighborhood_batch(
        self,
        start_node_ids: list[str],
        max_depth: int,
    ) -> list[CodeContextNode]:
        del start_node_ids, max_depth
        return list(self.nodes)

    def fetch_taint_sources(
        self,
        root_node_ids: list[str],
        max_taint_depth: int = 6,
    ) -> dict[NodeID, float]:
        del root_node_ids, max_taint_depth
        return {}

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


def _write_file(tmp_path: Path, content: str) -> None:
    (tmp_path / "app.py").write_text(content, encoding="utf-8")


def test_path_fill_includes_intermediate_call_even_at_low_score(tmp_path: Path) -> None:
    """A low-score function on the call path from root to a high-score sink must be rendered."""

    _write_file(
        tmp_path,
        "def root_anchor():\n"  # line 1
        "    return middle_helper()\n"  # line 2
        "def middle_helper():\n"  # line 3
        "    return sink_call()\n"  # line 4
        "def sink_call():\n"  # line 5
        "    return 1\n",  # line 6
    )

    root = _make_node("root_anchor", line_start=1, line_end=2, depth=0, score=1.0)
    middle = _make_node("middle_helper", line_start=3, line_end=4, depth=1, score=0.10)
    sink = _make_node("sink_call", line_start=5, line_end=6, depth=2, score=0.90)

    edges: list[tuple[NodeID, NodeID, str]] = [
        (root.identifier, middle.identifier, "CALLS"),
        (middle.identifier, sink.identifier, "CALLS"),
    ]

    repo = _StubRepo.model_construct(
        client=None,
        traversal_relationship_types=(),
        path_fill_edge_types=("CALLS",),
        nodes=[root, middle, sink],
        edges=edges,
    )
    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=repo,
        max_call_depth=4,
        token_budget=1_000,
        ranking_strategy=_ScoreSortStrategy(),
    )

    context = service.assemble_for_spans(
        tmp_path,
        [FileSpans(tmp_path / "app.py", [(1, 1)])],
    )

    assert "def root_anchor" in context.context_text
    assert "def sink_call" in context.context_text
    assert "def middle_helper" in context.context_text


def test_path_fill_evicts_low_score_leaf_to_make_room_for_companion(tmp_path: Path) -> None:
    """When budget is tight, drop the lowest-score leaf rather than the companion path."""

    _write_file(
        tmp_path,
        "def root_anchor():\n"
        "    return helper()\n"
        "def helper():\n"
        "    return sink_call()\n"
        "def sink_call():\n"
        "    return 1\n"
        "def unrelated_leaf():\n"
        "    return 0\n",
    )

    root = _make_node("root_anchor", line_start=1, line_end=2, depth=0, score=1.0)
    helper = _make_node("helper", line_start=3, line_end=4, depth=1, score=0.05)
    sink = _make_node("sink_call", line_start=5, line_end=6, depth=2, score=0.95)
    leaf = _make_node("unrelated_leaf", line_start=7, line_end=8, depth=1, score=0.30)

    edges: list[tuple[NodeID, NodeID, str]] = [
        (root.identifier, helper.identifier, "CALLS"),
        (helper.identifier, sink.identifier, "CALLS"),
        (root.identifier, leaf.identifier, "CALLS"),
    ]

    repo = _StubRepo.model_construct(
        client=None,
        traversal_relationship_types=(),
        path_fill_edge_types=("CALLS",),
        nodes=[root, helper, sink, leaf],
        edges=edges,
    )
    # Budget allows root + leaf + sink (~6 lines) but not all four.
    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=repo,
        max_call_depth=4,
        token_budget=40,
        ranking_strategy=_ScoreSortStrategy(),
    )

    context = service.assemble_for_spans(
        tmp_path,
        [FileSpans(tmp_path / "app.py", [(1, 1)])],
    )

    assert "def root_anchor" in context.context_text
    assert "def helper" in context.context_text, (
        "helper is a required companion of high-score sink and must survive eviction"
    )
    assert "def sink_call" in context.context_text
    assert "def unrelated_leaf" not in context.context_text, (
        "lower-score unrelated leaf should be evicted before the companion path"
    )


def test_path_fill_disconnected_node_still_included_when_budget_allows(
    tmp_path: Path,
) -> None:
    """Nodes with no path to a root in the fetched neighborhood are not blocked."""

    _write_file(
        tmp_path,
        "def root_anchor():\n    pass\ndef detached():\n    pass\n",
    )

    root = _make_node("root_anchor", line_start=1, line_end=2, depth=0, score=1.0)
    detached = _make_node("detached", line_start=3, line_end=4, depth=1, score=0.5)

    repo = _StubRepo.model_construct(
        client=None,
        traversal_relationship_types=(),
        path_fill_edge_types=("CALLS",),
        nodes=[root, detached],
        edges=[],
    )
    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=repo,
        max_call_depth=4,
        token_budget=1_000,
        ranking_strategy=_ScoreSortStrategy(),
    )

    context = service.assemble_for_spans(
        tmp_path,
        [FileSpans(tmp_path / "app.py", [(1, 1)])],
    )

    assert "def root_anchor" in context.context_text
    assert "def detached" in context.context_text
