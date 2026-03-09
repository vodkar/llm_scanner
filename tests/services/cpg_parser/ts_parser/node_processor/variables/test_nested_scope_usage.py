from models.base import NodeID
from models.edges.data_flow import DataFlowUsedBy
from models.nodes import VariableNode
from models.nodes.code import FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_NESTED_SCOPE_FILE


def test_tree_sitter_parse__nested_scope__emits_used_by_for_closure_variable() -> None:
    """Variable ``x`` defined in ``outer`` is used by ``inner`` — should emit USED_BY."""
    parser = CPGFileBuilder(path=TEST_NESTED_SCOPE_FILE)

    nodes, edges = parser.build()

    data = TEST_NESTED_SCOPE_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    # ``x = 10`` inside outer()
    x_sb = idx(b"x = 10")
    x_id = NodeID.create("variable", "x", str(TEST_NESTED_SCOPE_FILE), x_sb)
    assert x_id in nodes
    assert isinstance(nodes[x_id], VariableNode)

    # inner() function definition
    inner_sb = idx(b"def inner()")
    inner_id = NodeID.create("function", "inner", str(TEST_NESTED_SCOPE_FILE), inner_sb)
    assert inner_id in nodes
    assert isinstance(nodes[inner_id], FunctionNode)

    # ``y = x + 1`` references closure variable ``x`` — USED_BY expected
    used_by_edge = DataFlowUsedBy(src=x_id, dst=inner_id)
    assert used_by_edge in edges


def test_tree_sitter_parse__nested_scope__y_variable_created() -> None:
    """Variable ``y`` should be created inside ``inner``."""
    parser = CPGFileBuilder(path=TEST_NESTED_SCOPE_FILE)

    nodes, _edges = parser.build()

    data = TEST_NESTED_SCOPE_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    y_sb = idx(b"y = ")
    y_id = NodeID.create("variable", "y", str(TEST_NESTED_SCOPE_FILE), y_sb)
    assert y_id in nodes
    assert isinstance(nodes[y_id], VariableNode)
    assert nodes[y_id].name == "y"
