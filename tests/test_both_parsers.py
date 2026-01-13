# from pathlib import Path

# import pytest

# from entrypoints.base import parse_file_to_cpg, parse_project_to_cpg
# from models.edges import EdgeType
# from models.nodes import FunctionNode, ModuleNode
# from tests.consts import SAMPLE_FILE, SAMPLE_PROJECT_ROOT


# def test_parse_sample():
#     """Test that both parsers produce similar CPG structure for sample file."""
#     # Use a more robust way to locate test files
#     if not SAMPLE_FILE.exists():
#         pytest.skip(f"Test file not found: {SAMPLE_FILE}")

#     nodes, edges = parse_file_to_cpg(SAMPLE_FILE)

#     modules = [n for n in nodes.values() if isinstance(n, ModuleNode)]
#     assert modules, "Module nodes should exist"

#     functions = [n for n in nodes.values() if isinstance(n, FunctionNode)]
#     assert any(fn.name == "demo" for fn in functions)

#     funcs = {
#         node.module_name: node_id
#         for node_id, node in nodes.items()
#         if isinstance(node, FunctionNode)
#     }
#     demo_id = funcs.get("sample.demo") or funcs.get("demo")
#     export_id = next(
#         (
#             node_id
#             for qual, node_id in funcs.items()
#             if qual.endswith("export_orders_csv")
#         ),
#         None,
#     )

#     if demo_id and export_id:
#         assert any(
#             e.type == EdgeType.CALLS and e.src == demo_id and e.dst == export_id
#             for e in edges
#         )


# def test_parse_project():
#     """Test that both parsers handle cross-file calls in projects."""
#     # Use a more robust way to locate test project
#     if not SAMPLE_PROJECT_ROOT.exists():
#         pytest.skip(f"Test project not found: {SAMPLE_PROJECT_ROOT}")

#     nodes, __edges = parse_project_to_cpg(SAMPLE_PROJECT_ROOT)

#     assert any(
#         isinstance(node, ModuleNode) and "sample_project" in Path(node.file_path).parts
#         for node in nodes.values()
#     )
#     funcs = {
#         node.module_name: node_id
#         for node_id, node in nodes.items()
#         if isinstance(node, FunctionNode)
#     }

#     # Should have greet and run functions - make these explicit assertions
#     greet_id = next(
#         (nid for q, nid in funcs.items() if q.endswith("utils.greet")), None
#     )
#     run_id = next((nid for q, nid in funcs.items() if q.endswith("main.run")), None)

#     assert (
#         greet_id is not None
#     ), f"Expected to find utils.greet function, available functions: {list(funcs.keys())}"
#     assert (
#         run_id is not None
#     ), f"Expected to find main.run function, available functions: {list(funcs.keys())}"
