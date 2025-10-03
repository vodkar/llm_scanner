from pathlib import Path
from enum import Enum

from models.edge import Edge
from models.node import Node
from services.ast_cpg_parser import AstCPGParser
from services.tree_sitter_cpg_parser import (
    TreeSitterCPGParser,
)
from services.cpg_parser_interface import CPGParserProtocol


class ParserType(Enum):
    AST = "ast"
    TREE_SITTER = "tree_sitter"


def get_parser(parser_type: ParserType = ParserType.AST) -> CPGParserProtocol:
    """Get a CPG parser instance of the specified type.

    Args:
        parser_type: The type of parser to create

    Returns:
        A CPG parser implementing the common interface

    Raises:
        ImportError: If tree_sitter is requested but not available
        ValueError: If an unknown parser type is requested
    """
    if parser_type == ParserType.AST:
        return AstCPGParser()
    elif parser_type == ParserType.TREE_SITTER:
        return TreeSitterCPGParser()
    else:
        raise ValueError(f"Unknown parser type: {parser_type}")


def parse_file_to_cpg(
    path: Path, ignore_magic: bool = True, parser_type: ParserType = ParserType.AST
) -> tuple[dict[str, Node], list[Edge]]:
    """Parse a single file into a CPG.

    Args:
        path: Path to the Python file to parse
        ignore_magic: Whether to ignore magic methods (__init__, __str__, etc.)
        parser_type: Which parser implementation to use

    Returns:
        Tuple of (nodes_dict, edges_list)

    Raises:
        ValueError: If path contains security issues or is invalid
    """
    # Security validation - resolve path to prevent path traversal
    try:
        resolved_path = path.resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {path} - {e}") from e

    # Additional security checks could be added here if needed
    # (e.g., checking against allowed directories, file size limits, etc.)

    parser = get_parser(parser_type)
    return parser.parse_file(resolved_path, ignore_magic=ignore_magic)


def parse_project_to_cpg(
    root: Path, ignore_magic: bool = True, parser_type: ParserType = ParserType.AST
) -> tuple[dict[str, Node], list[Edge]]:
    """Parse a multi-file project folder into a single CPG.

    Args:
        root: Directory path containing a Python package or project
        ignore_magic: Whether to ignore magic methods
        parser_type: Which parser implementation to use

    Returns:
        Tuple of (nodes_dict, edges_list)

    Raises:
        ValueError: If path contains security issues or is invalid
    """
    # Security validation - resolve path to prevent path traversal
    try:
        resolved_root = root.resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {root} - {e}") from e

    # Additional security checks could be added here if needed
    # (e.g., checking against allowed directories, project size limits, etc.)

    parser = get_parser(parser_type)
    return parser.parse_project(resolved_root, ignore_magic=ignore_magic)
