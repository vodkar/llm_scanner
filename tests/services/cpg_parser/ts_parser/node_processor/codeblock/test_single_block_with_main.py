from models.base import NodeID
from models.nodes.code import CodeBlockNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index
from .consts import TEST_SINGLE_BLOCK_WITH_MAIN_FILE


def test_tree_sitter_parse__on_class__returns_correct_nodes_and_edges() -> None:
    parser = CPGFileBuilder(path=TEST_SINGLE_BLOCK_WITH_MAIN_FILE)

    nodes, _edges = parser.build()

    data: bytes = TEST_SINGLE_BLOCK_WITH_MAIN_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    code_block_nodes: list[CodeBlockNode] = [
        node for node in nodes.values() if isinstance(node, CodeBlockNode)
    ]

    assert len(code_block_nodes) == 1

    code_block_sb: int = idx(b"a = ")
    code_block_id: NodeID = NodeID.create(
        "code_block",
        "a = 1",
        str(TEST_SINGLE_BLOCK_WITH_MAIN_FILE),
        code_block_sb,
    )

    assert code_block_id in nodes
    assert nodes[code_block_id] == CodeBlockNode(
        identifier=code_block_id,
        file_path=TEST_SINGLE_BLOCK_WITH_MAIN_FILE,
        line_start=1,
        line_end=5,
    )
