from models.base import NodeID
from models.edges.call_graph import CallGraphCalls
from models.edges.data_flow import DataFlowDefinedBy, DefinitionOperation
from models.nodes import (
    FunctionNode,
    VariableNode,
)
from models.nodes.code import ClassNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.consts import TEST_SIMPLE_VARIABLES_FILE
from tests.utils import symbol_byte_index


def test_tree_sitter_parse__on_class__returns_correct_nodes_and_edges() -> None:
    parser = CPGFileBuilder(path=TEST_SIMPLE_VARIABLES_FILE)

    nodes, _edges = parser.build()

    data = TEST_SIMPLE_VARIABLES_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    assert len(nodes) == 4
    assert len(_edges) == 5

    a_def_sb = idx(b"a = 1")
    a_def_id = NodeID.create("variable", "a", str(TEST_SIMPLE_VARIABLES_FILE), a_def_sb)

    b_def_sb = idx(b"b = ")
    b_def_id = NodeID.create("variable", "b", str(TEST_SIMPLE_VARIABLES_FILE), b_def_sb)

    c_def_sb = idx(b"c = ")
    c_def_id = NodeID.create("variable", "c", str(TEST_SIMPLE_VARIABLES_FILE), c_def_sb)

    d_def_sb = idx(b"d = ")
    d_def_id = NodeID.create("variable", "d", str(TEST_SIMPLE_VARIABLES_FILE), d_def_sb)

    assert a_def_id in nodes
    assert nodes[a_def_id] == VariableNode(
        identifier=a_def_id,
        name="a",
        file_path=TEST_SIMPLE_VARIABLES_FILE,
        line_start=1,
        line_end=1,
    )

    assert b_def_id in nodes
    assert nodes[b_def_id] == VariableNode(
        identifier=b_def_id,
        name="b",
        file_path=TEST_SIMPLE_VARIABLES_FILE,
        line_start=2,
        line_end=2,
    )

    assert (
        DataFlowDefinedBy(
            src=a_def_id, dst=b_def_id, operation=DefinitionOperation.ASSIGNMENT
        )
        in _edges
    )

    assert c_def_id in nodes
    assert nodes[c_def_id] == VariableNode(
        identifier=c_def_id,
        name="c",
        file_path=TEST_SIMPLE_VARIABLES_FILE,
        line_start=3,
        line_end=3,
    )
    assert (
        DataFlowDefinedBy(
            src=a_def_id, dst=c_def_id, operation=DefinitionOperation.ASSIGNMENT
        )
        in _edges
    )
    assert (
        DataFlowDefinedBy(
            src=b_def_id, dst=c_def_id, operation=DefinitionOperation.ASSIGNMENT
        )
        in _edges
    )

    assert d_def_id in nodes
    assert nodes[d_def_id] == VariableNode(
        identifier=d_def_id,
        name="d",
        file_path=TEST_SIMPLE_VARIABLES_FILE,
        line_start=4,
        line_end=4,
    )
    assert (
        DataFlowDefinedBy(
            src=c_def_id, dst=d_def_id, operation=DefinitionOperation.ASSIGNMENT
        )
        in _edges
    )
    assert (
        DataFlowDefinedBy(
            src=b_def_id, dst=d_def_id, operation=DefinitionOperation.ASSIGNMENT
        )
        in _edges
    )
