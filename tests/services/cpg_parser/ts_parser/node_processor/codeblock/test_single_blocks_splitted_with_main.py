from models.base import NodeID
from models.nodes.code import CodeBlockNode
from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
from tests.utils import symbol_byte_index

from .consts import TEST_BLOCKS_SPLITTED_BY_FUNC_FILE


def test_tree_sitter_parse__on_class__returns_correct_nodes_and_edges() -> None:
    parser = CPGFileBuilder(path=TEST_BLOCKS_SPLITTED_BY_FUNC_FILE)

    nodes, _edges = parser.build()

    data: bytes = TEST_BLOCKS_SPLITTED_BY_FUNC_FILE.read_bytes()

    def idx(needle: bytes, start: int = 0) -> int:
        return symbol_byte_index(data, needle, start)

    code_block_nodes: list[CodeBlockNode] = [
        node for node in nodes.values() if isinstance(node, CodeBlockNode)
    ]

    assert len(code_block_nodes) == 2

    first_code_block_sb: int = idx(b"a = ")
    first_code_block_id: NodeID = NodeID.create(
        "code_block",
        "a = 1",
        str(TEST_BLOCKS_SPLITTED_BY_FUNC_FILE),
        first_code_block_sb,
    )

    assert first_code_block_id in nodes
    assert nodes[first_code_block_id] == CodeBlockNode(
        identifier=first_code_block_id,
        file_path=TEST_BLOCKS_SPLITTED_BY_FUNC_FILE,
        line_start=1,
        line_end=2,
    )

    second_code_block_sb: int = idx(b"sample =")
    second_code_bloack_id: NodeID = NodeID.create(
        "code_block",
        "sample = [3, 2, 1]",
        str(TEST_BLOCKS_SPLITTED_BY_FUNC_FILE),
        second_code_block_sb,
    )

    assert second_code_bloack_id in nodes
    assert nodes[second_code_bloack_id] == CodeBlockNode(
        identifier=second_code_bloack_id,
        file_path=TEST_BLOCKS_SPLITTED_BY_FUNC_FILE,
        line_start=7,
        line_end=7,
    )
