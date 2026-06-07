"""Tests for structural pruning of hub-mediated context nodes."""

from pathlib import Path
from typing import Any

from models.base import NodeID
from models.context import CodeContextNode
from repositories.context import ContextRepository
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import DummyNodeRankingStrategy


class _EdgeRepo(ContextRepository):
    """Stub returning a fixed neighborhood plus fixed edges."""

    nodes: list[CodeContextNode]
    edges: list[tuple[NodeID, NodeID, str]]

    def model_post_init(self, __context: Any) -> None:
        del __context

    def fetch_code_neighborhood_batch(
        self, start_node_ids: list[str], max_depth: int
    ) -> list[CodeContextNode]:
        del start_node_ids, max_depth
        return list(self.nodes)

    def fetch_enclosing_class_nodes(self, root_ids: list[str]) -> list[CodeContextNode]:
        del root_ids
        return []

    def fetch_neighborhood_edges(
        self,
        node_ids: list[str],
        edge_types: tuple[str, ...] | None = None,
    ) -> list[tuple[NodeID, NodeID, str]]:
        del node_ids, edge_types
        return list(self.edges)


def _node(name: str, *, depth: int) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"function:{name}"),
        node_kind="FunctionNode",
        name=name,
        file_path=Path("pkg/mod.py"),
        line_start=1,
        line_end=2,
        depth=depth,
    )


def _calls(src: str, dst: str) -> tuple[NodeID, NodeID, str]:
    return (NodeID(f"function:{src}"), NodeID(f"function:{dst}"), "CALLS")


def _service(
    nodes: list[CodeContextNode],
    edges: list[tuple[NodeID, NodeID, str]],
    *,
    damp: bool = True,
    threshold: int = 12,
) -> ContextAssemblerService:
    repo = _EdgeRepo.model_construct(
        client=None,
        nodes=nodes,
        edges=edges,
        traversal_relationship_types=(),
    )
    return ContextAssemblerService(
        project_root=Path("/nonexistent"),
        context_repository=repo,
        max_call_depth=3,
        token_budget=1_000,
        ranking_strategy=DummyNodeRankingStrategy(),
        exclude_test_nodes=False,
        damp_call_graph_hubs=damp,
        hub_fanin_threshold=threshold,
    )


def _scenario() -> tuple[list[CodeContextNode], list[tuple[NodeID, NodeID, str]]]:
    """root -> A -> B real chain; root -> hub; hub <- 12 unrelated callers."""

    nodes = [_node("root", depth=0), _node("A", depth=1), _node("B", depth=2)]
    nodes.append(_node("hub", depth=1))
    edges = [_calls("root", "A"), _calls("A", "B"), _calls("root", "hub")]
    for i in range(12):
        nodes.append(_node(f"C{i}", depth=2))
        edges.append(_calls("hub", f"C{i}"))
    return nodes, edges


def _names(nodes: list[CodeContextNode]) -> set[str | None]:
    return {n.name for n in nodes}


def test_prunes_hub_mediated_callers_keeps_real_chain_and_hub() -> None:
    """Callers reachable only via a fan-in hub are dropped; chain + hub kept."""

    nodes, edges = _scenario()
    service = _service(nodes, edges)

    result = service.fetch_context_nodes_for_root_ids(["function:root"])

    assert _names(result) == {"root", "A", "B", "hub"}


def test_no_pruning_when_below_threshold() -> None:
    """A node below the fan-in threshold is not treated as a hub."""

    nodes, edges = _scenario()
    service = _service(nodes, edges, threshold=50)

    result = service.fetch_context_nodes_for_root_ids(["function:root"])

    assert "C0" in _names(result) and "C11" in _names(result)


def test_flag_off_keeps_everything() -> None:
    """With damp_call_graph_hubs=False nothing is pruned."""

    nodes, edges = _scenario()
    service = _service(nodes, edges, damp=False)

    result = service.fetch_context_nodes_for_root_ids(["function:root"])

    assert len(_names(result)) == len(nodes)


def test_high_degree_root_is_never_pruned() -> None:
    """A root with high fan-in is kept and seeds reachability for its callees."""

    nodes = [_node("root", depth=0)]
    edges: list[tuple[NodeID, NodeID, str]] = []
    for i in range(15):
        nodes.append(_node(f"D{i}", depth=1))
        edges.append(_calls("root", f"D{i}"))

    service = _service(nodes, edges)
    result = service.fetch_context_nodes_for_root_ids(["function:root"])

    assert "root" in _names(result)
    assert _names(result) == {n.name for n in nodes}
