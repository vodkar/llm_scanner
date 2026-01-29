from models.base import NodeID
from models.nodes.call_site import CallNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_METHOD_CALLS_FILE


def test_tree_sitter_parse__on_class_passed_as_argument__creates_dataflow_edge() -> None:
    parser = CPGFileBuilder(path=TEST_METHOD_CALLS_FILE)
    data: bytes = TEST_METHOD_CALLS_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    nodes, edges = parser.build()

    method_sb: int = idx(b"def print(self)")
    method_id: NodeID = NodeID.create(
        "function",
        "print",
        str(TEST_METHOD_CALLS_FILE),
        method_sb,
    )
    assert method_id in nodes

    main_sb: int = idx(b"def main()")
    main_id: NodeID = NodeID.create(
        "function",
        "main",
        str(TEST_METHOD_CALLS_FILE),
        main_sb,
    )
    assert main_id in nodes

    call_sb: int = idx(b"a.print()", main_sb)
    call_id: NodeID = NodeID.create(
        "call",
        "print()",
        str(TEST_METHOD_CALLS_FILE),
        call_sb,
    )
    assert call_id in nodes

    assert nodes[call_id] == CallNode(
        identifier=call_id,
        callee_id=method_id,
        caller_id=main_id,
        line_start=5,
        line_end=5,
        file_path=TEST_METHOD_CALLS_FILE,
    )
