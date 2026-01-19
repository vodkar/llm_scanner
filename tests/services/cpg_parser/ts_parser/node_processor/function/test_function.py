from models.base import NodeID
from models.nodes.code import FunctionNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index
from .consts import TEST_SIMPLE_FUNCTION_FILE


def test_tree_sitter_parse__on_single_function__returns_correct_function() -> None:
    parser = CPGFileBuilder(path=TEST_SIMPLE_FUNCTION_FILE)

    nodes, _edges = parser.build()

    data: bytes = TEST_SIMPLE_FUNCTION_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    assert (
        len(list(filter(lambda node: isinstance(node, FunctionNode), nodes.values())))
        == 1
    )

    function_sb: int = idx(b"def sample_function_body")
    function_id: NodeID = NodeID.create(
        "function",
        "sample_function_body",
        str(TEST_SIMPLE_FUNCTION_FILE),
        function_sb,
    )

    assert function_id in nodes
    assert nodes[function_id] == FunctionNode(
        identifier=function_id,
        name="sample_function_body",
        file_path=TEST_SIMPLE_FUNCTION_FILE,
        line_start=1,
        line_end=7,
    )
