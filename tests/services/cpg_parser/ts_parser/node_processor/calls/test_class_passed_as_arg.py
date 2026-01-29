from models.base import NodeID
from models.edges.data_flow import DataFlowFlowsTo
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_CLASS_PASSED_AS_ARG_FILE


def test_tree_sitter_parse__on_class_passed_as_argument__creates_dataflow_edge() -> None:
    parser = CPGFileBuilder(path=TEST_CLASS_PASSED_AS_ARG_FILE)

    nodes, edges = parser.build()

    data: bytes = TEST_CLASS_PASSED_AS_ARG_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    class_sb: int = idx(b"class C")
    class_id: NodeID = NodeID.create(
        "class",
        "C",
        str(TEST_CLASS_PASSED_AS_ARG_FILE),
        class_sb,
    )
    assert class_id in nodes

    foo_sb: int = idx(b"def foo")
    foo_id: NodeID = NodeID.create(
        "function",
        "foo",
        str(TEST_CLASS_PASSED_AS_ARG_FILE),
        foo_sb,
    )
    assert foo_id in nodes

    call_sb: int = idx(b"use(C)", foo_sb)
    call_id: NodeID = NodeID.create(
        "call",
        "use(C)",
        str(TEST_CLASS_PASSED_AS_ARG_FILE),
        call_sb,
    )
    assert call_id in nodes

    assert DataFlowFlowsTo(src=class_id, dst=call_id) in edges
