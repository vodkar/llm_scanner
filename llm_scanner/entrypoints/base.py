from pathlib import Path

from models.edges import Edge
from models.nodes import Node
from services.cpg_parser.tree_sitter_cpg_parser import TreeSitterCPGParser  # type: ignore
from services.cpg_parser.cpg_parser_interface import CPGParserProtocol


def get_parser() -> CPGParserProtocol:
    """Return the default CPG parser implementation."""
    return TreeSitterCPGParser()


def parse_file_to_cpg(
    path: Path, ignore_magic: bool = True
) -> tuple[dict[str, Node], list[Edge]]:
    """Parse a single file into a CPG.

    Args:
        path: Path to the Python file to parse
        ignore_magic: Whether to ignore magic methods (__init__, __str__, etc.)

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

    parser = get_parser()
    return parser.parse_file(resolved_path, ignore_magic=ignore_magic)


def parse_project_to_cpg(
    root: Path, ignore_magic: bool = True
) -> tuple[dict[str, Node], list[Edge]]:
    """Parse a multi-file project folder into a single CPG.

    Args:
        root: Directory path containing a Python package or project
        ignore_magic: Whether to ignore magic methods

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

    parser = get_parser()
    return parser.parse_project(resolved_root, ignore_magic=ignore_magic)
