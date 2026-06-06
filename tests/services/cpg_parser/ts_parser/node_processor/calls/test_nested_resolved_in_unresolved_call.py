from models.base import NodeID
from models.edges.call_graph import CallGraphCalledBy, CallGraphCalls
from models.nodes.call_site import CallNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_NESTED_RESOLVED_IN_UNRESOLVED_CALL_FILE


def test_resolved_inner_call_inside_unresolved_outer_creates_call_node_and_edges() -> None:
    """_sanitize(value) nested inside unresolved external_lib.snakecase(...)
    must produce a CallNode and CALLS/CALLED_BY edges from snake_case."""
    parser = CPGFileBuilder(path=TEST_NESTED_RESOLVED_IN_UNRESOLVED_CALL_FILE)
    nodes, edges = parser.build()

    data = TEST_NESTED_RESOLVED_IN_UNRESOLVED_CALL_FILE.read_bytes()
    path_str = str(TEST_NESTED_RESOLVED_IN_UNRESOLVED_CALL_FILE)

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    sanitize_sb = idx(b"def _sanitize")
    sanitize_id = NodeID.create("function", "_sanitize", path_str, sanitize_sb)

    snake_case_sb = idx(b"def snake_case")
    snake_case_id = NodeID.create("function", "snake_case", path_str, snake_case_sb)

    # The inner call site: _sanitize(value) inside snake_case's return expression
    call_sb = idx(b"_sanitize(value)", snake_case_sb)
    call_id = NodeID.create("call", "_sanitize(value)", path_str, call_sb)

    assert sanitize_id in nodes
    assert snake_case_id in nodes
    assert call_id in nodes, "CallNode for inner resolved call must be created"
    assert CallGraphCalls(src=snake_case_id, dst=call_id) in edges
    assert CallGraphCalledBy(src=call_id, dst=sanitize_id) in edges


def test_unresolved_outer_call_produces_no_call_node() -> None:
    """external_lib.snakecase is unresolved and must not produce a CallNode.
    Only the inner _sanitize(value) call should appear as a CallNode."""
    parser = CPGFileBuilder(path=TEST_NESTED_RESOLVED_IN_UNRESOLVED_CALL_FILE)
    nodes, _ = parser.build()

    call_nodes = [n for n in nodes.values() if isinstance(n, CallNode)]
    assert len(call_nodes) == 1, (
        f"Expected exactly 1 CallNode (_sanitize), got {len(call_nodes)}: {call_nodes}"
    )
    assert "_sanitize" in str(call_nodes[0].identifier)
