# from models.nodes import (
#     CodeBlockNode,
#     CodeBlockType,
#     FunctionNode,
#     ModuleNode,
#     VariableNode,
#     VariableScope,
# )
# from services.cpg_parser.tree_sitter_cpg_parser import TreeSitterCPGParser
# from tests.consts import SAMPLE_FILE


# def test_tree_sitter_structured_nodes_cover_types() -> None:
#     parser = TreeSitterCPGParser()
#     nodes, edges = parser.parse_file(SAMPLE_FILE)

#     assert nodes, "Expected structured nodes from sample file"
#     assert edges, "Expected edges from structured parse"

#     modules = [n for n in nodes.values() if isinstance(n, ModuleNode)]
#     assert modules, "Module node missing"
#     assert modules[0].is_entry_point is True
#     assert modules[0].imports, "Module imports should not be empty"

#     functions = [n for n in nodes.values() if isinstance(n, FunctionNode)]
#     assert any(fn.name == "demo" for fn in functions)
#     pay_fn = next(fn for fn in functions if fn.name == "pay")
#     assert pay_fn.has_decorators is True
#     assert pay_fn.num_parameters >= 2
#     assert pay_fn.signature.startswith("(")

#     code_blocks = [n for n in nodes.values() if isinstance(n, CodeBlockNode)]
#     assert any(cb.type == CodeBlockType.FOR for cb in code_blocks)
#     assert any(cb.type == CodeBlockType.IF for cb in code_blocks)

#     variables = [n for n in nodes.values() if isinstance(n, VariableNode)]
#     repo_param = next(
#         (
#             var
#             for var in variables
#             if var.name == "repo" and var.scope == VariableScope.PARAMETER
#         ),
#         None,
#     )
#     assert repo_param is not None
#     assert repo_param.line_number > 0
