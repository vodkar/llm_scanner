from models.base import NodeID
from models.edges.call_graph import CallGraphCalledBy, CallGraphCalls
from models.nodes.call_site import CallNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_FUNCTION_CALLS_FILE


def test_tree_sitter_parse__on_function_calls__creates_call_nodes_and_edges() -> None:
    """Ensure in-function calls create call nodes and edges."""
    parser = CPGFileBuilder(path=TEST_FUNCTION_CALLS_FILE)

    nodes, edges = parser.build()

    data: bytes = TEST_FUNCTION_CALLS_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    bar_sb: int = idx(b"def bar")
    bar_id: NodeID = NodeID.create(
        "function",
        "bar",
        str(TEST_FUNCTION_CALLS_FILE),
        bar_sb,
    )

    foo_sb: int = idx(b"def foo")
    foo_id: NodeID = NodeID.create(
        "function",
        "foo",
        str(TEST_FUNCTION_CALLS_FILE),
        foo_sb,
    )

    baz_sb: int = idx(b"def baz")
    baz_id: NodeID = NodeID.create(
        "function",
        "baz",
        str(TEST_FUNCTION_CALLS_FILE),
        baz_sb,
    )

    assert bar_id in nodes
    assert foo_id in nodes
    assert baz_id in nodes

    bar_call_sb: int = idx(b"bar()", foo_sb)
    bar_call_id: NodeID = NodeID.create(
        "call",
        "bar()",
        str(TEST_FUNCTION_CALLS_FILE),
        bar_call_sb,
    )
    assert bar_call_id in nodes
    assert nodes[bar_call_id] == CallNode(
        identifier=bar_call_id,
        caller_id=foo_id,
        callee_id=bar_id,
        line_start=6,
        line_end=6,
        file_path=TEST_FUNCTION_CALLS_FILE,
    )

    nested_bar_call_sb: int = idx(b"bar()", baz_sb)
    nested_bar_call_id: NodeID = NodeID.create(
        "call",
        "bar()",
        str(TEST_FUNCTION_CALLS_FILE),
        nested_bar_call_sb,
    )
    assert nested_bar_call_id in nodes

    foo_call_sb: int = idx(b"foo(bar())", baz_sb)
    foo_call_id: NodeID = NodeID.create(
        "call",
        "foo(bar())",
        str(TEST_FUNCTION_CALLS_FILE),
        foo_call_sb,
    )
    assert foo_call_id in nodes

    assert (
        CallGraphCalls(
            src=foo_id,
            dst=bar_call_id,
            is_direct=True,
            call_depth=0,
        )
        in edges
    )
    assert (
        CallGraphCalledBy(
            src=bar_call_id,
            dst=bar_id,
        )
        in edges
    )

    assert (
        CallGraphCalls(
            src=baz_id,
            dst=foo_call_id,
            is_direct=True,
            call_depth=0,
        )
        in edges
    )
    assert (
        CallGraphCalledBy(
            src=foo_call_id,
            dst=foo_id,
        )
        in edges
    )

    assert (
        CallGraphCalls(
            src=baz_id,
            dst=nested_bar_call_id,
            is_direct=True,
            call_depth=0,
        )
        in edges
    )
    assert (
        CallGraphCalledBy(
            src=nested_bar_call_id,
            dst=bar_id,
        )
        in edges
    )
