"""Imports resolve when packages live under a source root such as ``src/``."""

from pathlib import Path
from typing import Final

from models.edges.call_graph import CallGraphCalledBy
from models.nodes.call_site import CallNode
from models.nodes.code import ClassNode, FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGDirectoryBuilder
from tests.consts import SRC_LAYOUT_PROJECT_ROOT

VHOST_FILE: Final[Path] = Path("src/webkit/vhost.py")


def test_src_layout__resolves_package_imports_relative_to_source_root() -> None:
    nodes, edges = CPGDirectoryBuilder(root=SRC_LAYOUT_PROJECT_ROOT).build()
    vhost_call_ids = {
        node_id
        for node_id, node in nodes.items()
        if isinstance(node, CallNode) and node.file_path == VHOST_FILE
    }

    callees: set[tuple[str, str]] = {
        (callee.name, str(callee.file_path))
        for edge in edges
        if isinstance(edge, CallGraphCalledBy) and edge.src in vhost_call_ids
        if isinstance(callee := nodes[edge.dst], FunctionNode | ClassNode)
    }

    assert ("ErrorPage", "src/webkit/resource.py") in callees
    assert ("safe_repr", "src/webkit/resource.py") in callees
