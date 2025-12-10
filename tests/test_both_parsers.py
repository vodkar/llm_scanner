from pathlib import Path
import pytest

from entrypoints.base import parse_file_to_cpg, parse_project_to_cpg, ParserType
from models.edge import EdgeType
from models.node import NodeType
from services.cpg_parser.cpg_parser_interface import CPGParserProtocol
from services.cpg_parser.tree_sitter_cpg_parser import TreeSitterCPGParser
from tests.consts import SAMPLE_FILE, SAMPLE_PROJECT_ROOT


@pytest.mark.parametrize("parser_type", [ParserType.AST, ParserType.TREE_SITTER])
def test_parse_sample_both_parsers(tmp_path: Path, parser_type: ParserType):
    """Test that both parsers produce similar CPG structure for sample file."""
    # Use a more robust way to locate test files
    if not SAMPLE_FILE.exists():
        pytest.skip(f"Test file not found: {SAMPLE_FILE}")

    try:
        nodes, edges = parse_file_to_cpg(SAMPLE_FILE, parser_type=parser_type)
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
    if not SAMPLE_PROJECT_ROOT.exists():
        pytest.skip(f"Test project not found: {SAMPLE_PROJECT_ROOT}")

    try:
        nodes, edges = parse_project_to_cpg(
            SAMPLE_PROJECT_ROOT, parser_type=parser_type
        )
    except ImportError:
        if parser_type == ParserType.TREE_SITTER:
            pytest.skip("tree-sitter dependencies not available")
        raise

    # Expect modules for main and utils - use enum value
    assert any(
        n.type == NodeType.MODULE and n.qualname.endswith("sample_project")
        for n in nodes.values()
    )
    funcs = {n.qualname: n.id for n in nodes.values() if n.type == NodeType.FUNCTION}

    # Should have greet and run functions - make these explicit assertions
    greet_id = next(
        (nid for q, nid in funcs.items() if q.endswith("utils.greet")), None
    )
    run_id = next((nid for q, nid in funcs.items() if q.endswith("main.run")), None)

    assert (
        greet_id is not None
    ), f"Expected to find utils.greet function, available functions: {list(funcs.keys())}"
    assert (
        run_id is not None
    ), f"Expected to find main.run function, available functions: {list(funcs.keys())}"

    # For now, only test cross-file calls for AST parser as Tree-sitter parser doesn't support this yet
    if parser_type == ParserType.AST:
        # Cross-file calls edge from main.run -> utils.greet
        calls_edges = [
            e
            for e in edges
            if e.type == EdgeType.CALLS and e.src == run_id and e.dst == greet_id
        ]
        assert (
            len(calls_edges) > 0
        ), f"Expected CALLS edge from main.run to utils.greet, total edges: {len(edges)}"
    else:
        # Tree-sitter parser currently doesn't detect cross-file calls
        # This is a known limitation - we just verify the basic structure exists
        pass


def test_parser_compatibility():
    """Test that both parsers implement the same interface."""
    from services.cpg_parser.ast_cpg_parser import AstCPGParser

    # AST parser should always be available
    ast_parser = AstCPGParser()
    assert isinstance(ast_parser, CPGParserProtocol)

    # Tree-sitter parser may not be available
    ts_parser = TreeSitterCPGParser()
    assert isinstance(ts_parser, CPGParserProtocol)
