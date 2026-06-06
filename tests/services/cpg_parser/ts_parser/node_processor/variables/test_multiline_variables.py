from models.base import NodeID
from models.nodes import (
    VariableNode,
)
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_MULTILINE_VARIABLES_FILE


def test_tree_sitter_parse__on_multiline_variables__returns_correct_nodes() -> None:
    parser = CPGFileBuilder(path=TEST_MULTILINE_VARIABLES_FILE)

    nodes, _edges = parser.build()

    data = TEST_MULTILINE_VARIABLES_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    assert len(list(filter(lambda n: isinstance(n, VariableNode), nodes.values()))) == 3

    a_def_sb = idx(b"a = [")
    a_def_id = NodeID.create("variable", "a", str(TEST_MULTILINE_VARIABLES_FILE), a_def_sb)

    b_def_sb = idx(b"b = {")
    b_def_id = NodeID.create("variable", "b", str(TEST_MULTILINE_VARIABLES_FILE), b_def_sb)

    c_def_sb = idx(b'c = """')
    c_def_id = NodeID.create("variable", "c", str(TEST_MULTILINE_VARIABLES_FILE), c_def_sb)

    assert a_def_id in nodes
    assert nodes[a_def_id] == VariableNode(
        identifier=a_def_id,
        name="a",
        file_path=TEST_MULTILINE_VARIABLES_FILE,
        line_start=1,
        line_end=5,
    )

    assert b_def_id in nodes
    assert nodes[b_def_id] == VariableNode(
        identifier=b_def_id,
        name="b",
        file_path=TEST_MULTILINE_VARIABLES_FILE,
        line_start=6,
        line_end=9,
    )

    assert c_def_id in nodes
    assert nodes[c_def_id] == VariableNode(
        identifier=c_def_id,
        name="c",
        file_path=TEST_MULTILINE_VARIABLES_FILE,
        line_start=10,
        line_end=13,
    )
