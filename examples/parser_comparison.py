#!/usr/bin/env python3
"""
Example showing how to use both CPG parser implementations.
"""

from pathlib import Path
from entrypoints.base import parse_file_to_cpg, ParserType, get_parser


def compare_parsers():
    """Compare AST and tree-sitter parsers on a sample file."""
    # Find a sample Python file to parse
    sample_file = Path(__file__).parent.parent / "tests" / "sample.py"
    
    if not sample_file.exists():
        print(f"Sample file not found: {sample_file}")
        return
    
    print(f"Parsing file: {sample_file}")
    print("=" * 50)
    
    # Parse with AST parser
    print("\n1. Using AST Parser:")
    try:
        ast_nodes, ast_edges = parse_file_to_cpg(sample_file, parser_type=ParserType.AST)
        print(f"   Nodes found: {len(ast_nodes)}")
        print(f"   Edges found: {len(ast_edges)}")
        
        # Show some node details
        for node_id, node in list(ast_nodes.items())[:3]:
            print(f"   - {node.type}: {node.name} (line {node.lineno})")
        
    except Exception as e:
        print(f"   Error: {e}")
    
    # Parse with tree-sitter parser
    print("\n2. Using Tree-sitter Parser:")
    try:
        ts_nodes, ts_edges = parse_file_to_cpg(sample_file, parser_type=ParserType.TREE_SITTER)
        print(f"   Nodes found: {len(ts_nodes)}")
        print(f"   Edges found: {len(ts_edges)}")
        
        # Show some node details  
        for node_id, node in list(ts_nodes.items())[:3]:
            print(f"   - {node.type}: {node.name} (line {node.lineno})")
            
    except ImportError:
        print("   Tree-sitter dependencies not installed")
        print("   Install with: pip install tree-sitter tree-sitter-python")
    except Exception as e:
        print(f"   Error: {e}")


def demonstrate_interface():
    """Demonstrate using the parser interface directly."""
    print("\n" + "=" * 50)
    print("Using Parser Interface Directly:")
    print("=" * 50)
    
    sample_file = Path(__file__).parent.parent / "tests" / "sample.py"
    
    if not sample_file.exists():
        print(f"Sample file not found: {sample_file}")
        return
    
    # Get AST parser instance
    try:
        ast_parser = get_parser(ParserType.AST)
        nodes, edges = ast_parser.parse_file(sample_file)
        print(f"\nAST Parser via interface: {len(nodes)} nodes, {len(edges)} edges")
    except Exception as e:
        print(f"AST Parser error: {e}")
    
    # Get tree-sitter parser instance
    try:
        ts_parser = get_parser(ParserType.TREE_SITTER)
        nodes, edges = ts_parser.parse_file(sample_file)
        print(f"Tree-sitter Parser via interface: {len(nodes)} nodes, {len(edges)} edges")
    except ImportError:
        print("Tree-sitter parser not available (dependencies not installed)")
    except Exception as e:
        print(f"Tree-sitter Parser error: {e}")


if __name__ == "__main__":
    compare_parsers()
    demonstrate_interface()