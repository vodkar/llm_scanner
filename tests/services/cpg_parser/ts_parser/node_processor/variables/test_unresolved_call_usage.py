from models.base import NodeID
from models.edges.data_flow import DataFlowUsedBy
from models.nodes import VariableNode
from models.nodes.code import FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_UNRESOLVED_CALL_FILE


def test_tree_sitter_parse__unresolved_call__emits_used_by_for_argument() -> None:
    """``print(data)`` inside ``main``: ``print`` is unresolved, but ``data``
    references a module-level variable — a USED_BY edge should be emitted."""
    parser = CPGFileBuilder(path=TEST_UNRESOLVED_CALL_FILE)

    nodes, edges = parser.build()

    data_bytes = TEST_UNRESOLVED_CALL_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data_bytes, needle, start)

    # module-level ``data = [1, 2, 3]``
    data_sb = idx(b"data =")
    data_id = NodeID.create("variable", "data", str(TEST_UNRESOLVED_CALL_FILE), data_sb)
    assert data_id in nodes
    assert isinstance(nodes[data_id], VariableNode)

    # function ``main``
    main_sb = idx(b"def main()")
    main_id = NodeID.create("function", "main", str(TEST_UNRESOLVED_CALL_FILE), main_sb)
    assert main_id in nodes
    assert isinstance(nodes[main_id], FunctionNode)

    # USED_BY via unresolved call argument
    used_by_edge = DataFlowUsedBy(src=data_id, dst=main_id)
    assert used_by_edge in edges


def test_tree_sitter_parse__unresolved_call__no_call_node_for_unresolved() -> None:
    """Unresolved calls (like ``print``) should NOT produce CallNode entries."""
    from models.nodes import CallNode

    parser = CPGFileBuilder(path=TEST_UNRESOLVED_CALL_FILE)

    nodes, _ = parser.build()

    call_nodes = [n for n in nodes.values() if isinstance(n, CallNode)]
    assert len(call_nodes) == 0, (
        f"Expected no CallNodes for unresolved calls, but found: {call_nodes}"
    )
