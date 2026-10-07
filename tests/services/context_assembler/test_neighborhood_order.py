"""The fetched context neighborhood must not depend on Neo4j's row order."""

from pathlib import Path

from models.base import NodeID
from models.context import CodeContextNode
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import DummyNodeRankingStrategy
from tests.services.context_assembler.test_path_fill import _StubRepo


def _node(name: str, file_name: str, line: int, depth: int) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"function:{name}"),
        node_kind="FunctionNode",
        name=name,
        file_path=Path(file_name),
        line_start=line,
        line_end=line,
        depth=depth,
    )


def _fetch(tmp_path: Path, nodes: list[CodeContextNode]) -> list[str]:
    repo = _StubRepo.model_construct(
        client=None,
        traversal_relationship_types=(),
        path_fill_edge_types=(),
        nodes=nodes,
        edges=[],
    )
    service = ContextAssemblerService(
        project_root=tmp_path,
        context_repository=repo,
        max_call_depth=3,
        token_budget=10_000,
        ranking_strategy=DummyNodeRankingStrategy(),
    )
    fetched = service.fetch_context_nodes_for_root_ids(["function:root"], requires_edge_paths=False)
    return [str(node.identifier) for node in fetched]


def test_fetch_context_nodes__order_is_independent_of_row_order(tmp_path: Path) -> None:
    nodes = [
        _node("root", "a.py", 1, 0),
        _node("helper_b", "b.py", 5, 1),
        _node("helper_a", "a.py", 9, 1),
        _node("deep", "a.py", 2, 2),
        _node("helper_c", "b.py", 5, 1),
    ]

    assert _fetch(tmp_path, nodes) == _fetch(tmp_path, list(reversed(nodes)))


def test_fetch_context_nodes__orders_by_depth_file_line_then_id(tmp_path: Path) -> None:
    nodes = [
        _node("deep", "a.py", 2, 2),
        _node("helper_c", "b.py", 5, 1),
        _node("helper_b", "b.py", 5, 1),
        _node("helper_a", "a.py", 9, 1),
        _node("root", "a.py", 1, 0),
    ]

    assert _fetch(tmp_path, nodes) == [
        "function:root",
        "function:helper_a",
        "function:helper_b",
        "function:helper_c",
        "function:deep",
    ]
