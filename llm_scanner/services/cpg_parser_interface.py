from pathlib import Path
from typing import Protocol, runtime_checkable

from models.edge import Edge
from models.node import Node


@runtime_checkable
class CPGParserProtocol(Protocol):
    """Protocol defining the interface for CPG parsers."""

    def parse_file(
        self, path: Path, ignore_magic: bool = True
    ) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a single file into a CPG.

        Args:
            path: Path to the Python file to parse
            ignore_magic: Whether to ignore magic methods (__init__, __str__, etc.)

        Returns:
            Tuple of (nodes_dict, edges_list)
        """
        ...

    def parse_project(
        self, root: Path, ignore_magic: bool = True
    ) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a project directory into a CPG.

        Args:
            root: Root directory of the project
            ignore_magic: Whether to ignore magic methods

        Returns:
            Tuple of (nodes_dict, edges_list)
        """
        ...
