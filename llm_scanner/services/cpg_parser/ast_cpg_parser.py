from pathlib import Path

from models.edges import Edge
from models.nodes import Node
from .cpg_parser import ASTCPGBuilderService, ProjectCPGBuilder
from .cpg_parser_interface import CPGParserProtocol
from utils.make_parseable_source import make_parseable_source


class AstCPGParser(CPGParserProtocol):
    """CPG parser implementation using Python's AST module."""

    def parse_file(
        self, path: Path, ignore_magic: bool = True
    ) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a single file using AST into a CPG.

        Args:
            path: Path to the Python file to parse
            ignore_magic: Whether to ignore magic methods (__init__, __str__, etc.)

        Returns:
            Tuple of (nodes_dict, edges_list)

        Raises:
            ValueError: If file cannot be read or path is invalid
        """
        if not path.exists():
            raise ValueError(f"File does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"Path is not a file: {path}")
        if path.suffix != ".py":
            raise ValueError(f"File is not a Python file: {path}")

        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to read file {path}: {e}") from e

        try:
            src = make_parseable_source(raw)
            builder = ASTCPGBuilderService(src, str(path), ignore_magic=ignore_magic)
            return builder.build()
        except Exception as e:
            raise ValueError(f"Failed to parse file {path}: {e}") from e

    def parse_project(
        self, root: Path, ignore_magic: bool = True
    ) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a project directory using AST into a CPG.

        Args:
            root: Root directory of the project
            ignore_magic: Whether to ignore magic methods

        Returns:
            Tuple of (nodes_dict, edges_list)

        Raises:
            ValueError: If directory cannot be accessed or is invalid
        """
        if not root.exists():
            raise ValueError(f"Directory does not exist: {root}")
        if not root.is_dir():
            raise ValueError(f"Path is not a directory: {root}")

        try:
            builder = ProjectCPGBuilder(root, ignore_magic=ignore_magic)
            return builder.build()
        except Exception as e:
            raise ValueError(f"Failed to parse project {root}: {e}") from e
