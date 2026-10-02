"""A nested class sharing a top-level class's name does not hijack its identity."""

from pathlib import Path

from models.edges.call_graph import CallGraphCalledBy
from models.nodes.call_site import CallNode
from models.nodes.code import FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from tests.consts import NESTED_CLASS_PROJECT_ROOT


def test_self_call_in_top_level_class__resolves_base_despite_nested_namesake() -> None:
    nodes, edges = CPGDirectoryBuilder(root=NESTED_CLASS_PROJECT_ROOT).build()
    call_ids = {
        node_id
        for node_id, node in nodes.items()
        if isinstance(node, CallNode)
        and node.file_path == Path("forms.py")
        and node.line_start == 12
    }

    callees = {
        (callee.name, callee.line_start)
        for edge in edges
        if isinstance(edge, CallGraphCalledBy) and edge.src in call_ids
        if isinstance(callee := nodes[edge.dst], FunctionNode)
    }

    assert callees == {("run", 2)}
