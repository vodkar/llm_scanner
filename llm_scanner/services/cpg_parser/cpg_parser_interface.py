from pathlib import Path
from typing import Protocol, runtime_checkable

from models.edges import Edge
from models.nodes import Node


@runtime_checkable
class CPGParserProtocol(Protocol):
    """Protocol defining the interface for CPG parsers."""

    def parse_file(
        self, path: Path, ignore_magic: bool = True
    ) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a single file into a structured CPG.

        Args:
            path: Path to the Python file that should be analyzed.
            ignore_magic: Whether to skip dunder methods during parsing.

        Returns:
            Tuple containing the structured nodes keyed by identifier and the
            edges referencing those identifiers.
        """
        ...

    def parse_project(
        self, root: Path, ignore_magic: bool = True
    ) -> tuple[dict[str, Node], list[Edge]]:
        """Parse a project directory into a structured CPG.

        Args:
            root: Root directory of the Python project to analyze.
            ignore_magic: Whether to skip dunder methods during parsing.

        Returns:
            Tuple containing the structured nodes keyed by identifier and the
            edges referencing those identifiers.
        """
        ...
