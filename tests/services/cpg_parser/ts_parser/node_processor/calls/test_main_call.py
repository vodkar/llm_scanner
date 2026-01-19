# from models.base import NodeID
# from models.nodes.call_site import CallNode
# from models.nodes.code import FunctionNode
# from services.cpg_parser.ts_parser.cpg_builder import CPGFileBuilder
# from tests.utils import symbol_byte_index
# from .consts import TEST_MAIN_FUNCTION_FILE


# def test_tree_sitter_parse__on_main_call__returns_correct_call() -> None:
#     parser = CPGFileBuilder(path=TEST_MAIN_FUNCTION_FILE)

#     nodes, _edges = parser.build()

#     data: bytes = TEST_MAIN_FUNCTION_FILE.read_bytes()

#     def idx(needle: bytes, start: int = 0) -> int:
#         return symbol_byte_index(data, needle, start)

#     assert len(nodes) == 3  # code block + function + main call

#     function_sb: int = idx(b"def main")
#     function_id: NodeID = NodeID.create(
#         "function",
#         "main",
#         str(TEST_MAIN_FUNCTION_FILE),
#         function_sb,
#     )

#     assert function_id in nodes

#     code_block_sb: int = idx(b"if __name__")
#     code_block_id: NodeID = NodeID.create(
#         "code_block",
#         'if __name__ == "__main__":',
#         str(TEST_MAIN_FUNCTION_FILE),
#         code_block_sb,
#     )
#     assert code_block_id in nodes

#     call_sb: int = idx(b"main()")
#     call_id: NodeID = NodeID.create(
#         "call",
#         "main()",
#         str(TEST_MAIN_FUNCTION_FILE),
#         call_sb,
#     )

#     assert call_id in nodes
#     assert nodes[call_id] == CallNode(
#         identifier=call_id,
#         callee_id=function_id,
#         caller_id=code_block_id,
#         qualified_name="main",
#         line_start=5,
#         line_end=5,
#         file_path=TEST_MAIN_FUNCTION_FILE,
#     )
