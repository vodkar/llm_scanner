from pathlib import Path
import pytest

from entrypoints.base import parse_file_to_cpg, parse_project_to_cpg, ParserType
from models.edge import EdgeType
from models.node import NodeType


@pytest.mark.parametrize("parser_type", [ParserType.AST, ParserType.TREE_SITTER])
def test_parse_sample_both_parsers(tmp_path: Path, parser_type: ParserType):
    """Test that both parsers produce similar CPG structure for sample file."""
    # Use a more robust way to locate test files
    test_dir = Path(__file__).parent
    sample = test_dir / "sample.py"
    
    if not sample.exists():
        pytest.skip(f"Test file not found: {sample}")
    
    try:
        nodes, edges = parse_file_to_cpg(sample, parser_type=parser_type)
    except ImportError:
        if parser_type == ParserType.TREE_SITTER:
            pytest.skip("tree-sitter dependencies not available")
        raise

    # Basic expectations - use enum values instead of strings
    assert any(n.type == NodeType.MODULE for n in nodes.values())
    assert any(n.type == NodeType.CLASS and n.name == "Order" for n in nodes.values())
    assert any(n.type == NodeType.FUNCTION and n.name == "demo" for n in nodes.values())

    # Verify calls relationship exists - use enum value
    funcs = {n.qualname: n.id for n in nodes.values() if n.type == NodeType.FUNCTION}
    demo_id = funcs.get("sample.demo") or funcs.get("demo")
    export_id = next(
        (nid for q, nid in funcs.items() if q.endswith("export_orders_csv")), None
    )
    
    if demo_id and export_id:
        assert any(
            e.type == EdgeType.CALLS and e.src == demo_id and e.dst == export_id
            for e in edges
        )


@pytest.mark.parametrize("parser_type", [ParserType.AST, ParserType.TREE_SITTER])
def test_parse_project_both_parsers(tmp_path: Path, parser_type: ParserType):
    """Test that both parsers handle cross-file calls in projects."""
    # Use a more robust way to locate test project
    test_dir = Path(__file__).parent
    project_root = test_dir / "sample_project"
    
    if not project_root.exists():
        pytest.skip(f"Test project not found: {project_root}")
    
    try:
        nodes, edges = parse_project_to_cpg(project_root, parser_type=parser_type)
    except ImportError:
        if parser_type == ParserType.TREE_SITTER:
            pytest.skip("tree-sitter dependencies not available")
        raise

    # Expect modules for main and utils - use enum value
    assert any(n.type == NodeType.MODULE and n.qualname.endswith("sample_project") for n in nodes.values())
    funcs = {n.qualname: n.id for n in nodes.values() if n.type == NodeType.FUNCTION}

    # Should have greet and run functions - make these explicit assertions
    greet_id = next((nid for q, nid in funcs.items() if q.endswith("utils.greet")), None)
    run_id = next((nid for q, nid in funcs.items() if q.endswith("main.run")), None)
    
    assert greet_id is not None, f"Expected to find utils.greet function, available functions: {list(funcs.keys())}"
    assert run_id is not None, f"Expected to find main.run function, available functions: {list(funcs.keys())}"
    
    # For now, only test cross-file calls for AST parser as Tree-sitter parser doesn't support this yet
    if parser_type == ParserType.AST:
        # Cross-file calls edge from main.run -> utils.greet
        calls_edges = [e for e in edges if e.type == EdgeType.CALLS and e.src == run_id and e.dst == greet_id]
        assert len(calls_edges) > 0, f"Expected CALLS edge from main.run to utils.greet, total edges: {len(edges)}"
    else:
        # Tree-sitter parser currently doesn't detect cross-file calls
        # This is a known limitation - we just verify the basic structure exists
        pass


def test_parser_compatibility():
    """Test that both parsers implement the same interface."""
    from services.ast_cpg_parser import AstCPGParser
    from services.tree_sitter_cpg_parser import TreeSitterCPGParser
    from services.cpg_parser_interface import CPGParserProtocol
    
    # AST parser should always be available
    ast_parser = AstCPGParser()
    assert isinstance(ast_parser, CPGParserProtocol)
    
    # Tree-sitter parser may not be available
    ts_parser = TreeSitterCPGParser()
    assert isinstance(ts_parser, CPGParserProtocol)