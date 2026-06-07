"""Tests for excluding test-code nodes from the assembled neighborhood."""

from pathlib import Path
from typing import Any

from models.base import NodeID
from models.context import CodeContextNode
from repositories.context import ContextRepository
from services.context_assembler.context_assembler import ContextAssemblerService
from services.ranking.ranking import DummyNodeRankingStrategy


class _NeighborhoodRepo(ContextRepository):
    """Repository stub returning a fixed neighborhood for both BFS branches."""

    nodes: list[CodeContextNode]

    def model_post_init(self, __context: Any) -> None:
        del __context

    def fetch_code_neighborhood_batch(
        self, start_node_ids: list[str], max_depth: int
    ) -> list[CodeContextNode]:
        del start_node_ids, max_depth
        return list(self.nodes)

    def fetch_code_neighborhood_with_edge_paths(
        self, start_node_ids: list[str], max_depth: int
    ) -> list[CodeContextNode]:
        del start_node_ids, max_depth
        return list(self.nodes)

    def fetch_enclosing_class_nodes(self, root_ids: list[str]) -> list[CodeContextNode]:
        del root_ids
        return []


def _node(
    name: str,
    file_path: str,
    *,
    depth: int,
) -> CodeContextNode:
    return CodeContextNode(
        identifier=NodeID(f"function:{name}"),
        node_kind="FunctionNode",
        name=name,
        file_path=Path(file_path),
        line_start=1,
        line_end=2,
        depth=depth,
    )


def _build_service(
    tmp_path: Path,
    nodes: list[CodeContextNode],
    *,
    exclude_test_nodes: bool = True,
) -> ContextAssemblerService:
    repo = _NeighborhoodRepo.model_construct(
        client=None,
        nodes=nodes,
        traversal_relationship_types=(),
    )
    return ContextAssemblerService(
        project_root=tmp_path,
        context_repository=repo,
        max_call_depth=2,
        token_budget=1_000,
        ranking_strategy=DummyNodeRankingStrategy(),
        exclude_test_nodes=exclude_test_nodes,
    )


def _names(nodes: list[CodeContextNode]) -> set[str | None]:
    return {node.name for node in nodes}


def test_excludes_test_function_keeps_root_and_helper(tmp_path: Path) -> None:
    """A test_* sibling reached via hubs is dropped; root and helper survive."""

    root = _node("run_query", "redash/query_runner/csv.py", depth=0)
    helper = _node("get_response", "redash/query_runner/csv.py", depth=1)
    test_fn = _node("test_run_query", "shuup_tests/front/test_runner.py", depth=1)

    service = _build_service(tmp_path, [root, helper, test_fn])
    nodes = service.fetch_context_nodes_for_root_ids([str(root.identifier)])

    assert _names(nodes) == {"run_query", "get_response"}


def test_excludes_node_in_file_importing_pytest(tmp_path: Path) -> None:
    """A normally-named node whose file imports pytest is dropped (content)."""

    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "helpers.py").write_text("import pytest\n\nx = 1\n", encoding="utf-8")

    root = _node("run_query", "redash/query_runner/csv.py", depth=0)
    pytest_helper = _node("make_widget", "pkg/helpers.py", depth=1)

    service = _build_service(tmp_path, [root, pytest_helper])
    nodes = service.fetch_context_nodes_for_root_ids([str(root.identifier)])

    assert _names(nodes) == {"run_query"}


def test_keeps_factories_without_test_import(tmp_path: Path) -> None:
    """A production factories.py with no test framework import is kept."""

    (tmp_path / "shuup" / "testing").mkdir(parents=True)
    (tmp_path / "shuup" / "testing" / "factories.py").write_text(
        "def get_default_shop():\n    return Shop()\n", encoding="utf-8"
    )

    root = _node("run_query", "redash/query_runner/csv.py", depth=0)
    factory = _node("get_default_shop", "shuup/testing/factories.py", depth=1)

    service = _build_service(tmp_path, [root, factory])
    nodes = service.fetch_context_nodes_for_root_ids([str(root.identifier)])

    assert _names(nodes) == {"run_query", "get_default_shop"}


def test_keeps_root_even_in_test_file(tmp_path: Path) -> None:
    """A root node is never dropped, even when it lives in a test file."""

    root = _node("test_thing", "tests/test_thing.py", depth=0)

    service = _build_service(tmp_path, [root])
    nodes = service.fetch_context_nodes_for_root_ids([str(root.identifier)])

    assert _names(nodes) == {"test_thing"}


def test_flag_off_keeps_test_nodes(tmp_path: Path) -> None:
    """With exclude_test_nodes=False nothing is filtered out."""

    root = _node("run_query", "redash/query_runner/csv.py", depth=0)
    test_fn = _node("test_run_query", "shuup_tests/front/test_runner.py", depth=1)

    service = _build_service(tmp_path, [root, test_fn], exclude_test_nodes=False)
    nodes = service.fetch_context_nodes_for_root_ids([str(root.identifier)])

    assert _names(nodes) == {"run_query", "test_run_query"}


def test_edge_path_branch_filters_test_nodes(tmp_path: Path) -> None:
    """The edge-path fetch branch filters test nodes identically."""

    root = _node("run_query", "redash/query_runner/csv.py", depth=0)
    test_fn = _node("test_run_query", "shuup_tests/front/test_runner.py", depth=1)

    service = _build_service(tmp_path, [root, test_fn])
    nodes = service.fetch_context_nodes_for_root_ids(
        [str(root.identifier)], requires_edge_paths=True
    )

    assert _names(nodes) == {"run_query"}
