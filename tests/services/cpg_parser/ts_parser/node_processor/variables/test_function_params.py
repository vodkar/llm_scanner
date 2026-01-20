from models.base import NodeID
from models.nodes import (
    VariableNode,
)
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from .consts import TEST_FUNCTION_PARAMS_FILE
from tests.utils import symbol_byte_index


def test_tree_sitter_parse__on_function_params__returns_correct_function_params() -> (
    None
):
    parser = CPGFileBuilder(path=TEST_FUNCTION_PARAMS_FILE)

    nodes, _edges = parser.build()

    data = TEST_FUNCTION_PARAMS_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    assert len(list(filter(lambda n: isinstance(n, VariableNode), nodes.values()))) == 6

    a_def_sb = idx(b"a,")
    a_def_id = NodeID.create("variable", "a", str(TEST_FUNCTION_PARAMS_FILE), a_def_sb)

    b_def_sb = idx(b"b: str")
    b_def_id = NodeID.create("variable", "b", str(TEST_FUNCTION_PARAMS_FILE), b_def_sb)

    c_def_sb = idx(b"c=")
    c_def_id = NodeID.create("variable", "c", str(TEST_FUNCTION_PARAMS_FILE), c_def_sb)

    assert a_def_id in nodes
    assert nodes[a_def_id] == VariableNode(
        identifier=a_def_id,
        name="a",
        file_path=TEST_FUNCTION_PARAMS_FILE,
        line_start=1,
        line_end=1,
    )

    assert b_def_id in nodes
    assert nodes[b_def_id] == VariableNode(
        identifier=b_def_id,
        name="b",
        file_path=TEST_FUNCTION_PARAMS_FILE,
        line_start=1,
        line_end=1,
        type_hint="str",
    )

    assert c_def_id in nodes
    assert nodes[c_def_id] == VariableNode(
        identifier=c_def_id,
        name="c",
        file_path=TEST_FUNCTION_PARAMS_FILE,
        line_start=1,
        line_end=1,
    )
