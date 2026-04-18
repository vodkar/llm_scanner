from models.base import NodeID
from models.edges.data_flow import DataFlowDefinedBy, DataFlowFlowsTo, DefinitionOperation
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_TAINT_CHAIN_FILE


def test_tree_sitter_parse__on_taint_chain__creates_multi_hop_dataflow_edges() -> None:
    """Multi-hop taint chain creates DEFINED_BY + FLOWS_TO edges end-to-end."""
    parser = CPGFileBuilder(path=TEST_TAINT_CHAIN_FILE)

    _nodes, edges = parser.build()

    data: bytes = TEST_TAINT_CHAIN_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    source_input_sb = idx(b"source_input = 1")
    source_input_id = NodeID.create(
        "variable", "source_input", str(TEST_TAINT_CHAIN_FILE), source_input_sb
    )

    a_sb = idx(b"a = source_input")
    a_id = NodeID.create("variable", "a", str(TEST_TAINT_CHAIN_FILE), a_sb)

    b_sb = idx(b"b = a")
    b_id = NodeID.create("variable", "b", str(TEST_TAINT_CHAIN_FILE), b_sb)

    sink_call_sb = idx(b"sink(b)")
    sink_call_id = NodeID.create("call", "sink(b)", str(TEST_TAINT_CHAIN_FILE), sink_call_sb)

    assert (
        DataFlowDefinedBy(src=source_input_id, dst=a_id, operation=DefinitionOperation.ASSIGNMENT)
        in edges
    )

    assert DataFlowDefinedBy(src=a_id, dst=b_id, operation=DefinitionOperation.ASSIGNMENT) in edges

    assert DataFlowFlowsTo(src=b_id, dst=sink_call_id) in edges
